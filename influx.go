package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/line-protocol/v2/lineprotocol"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
)

// The influx output controller, used to get InfluxDB lineprotocol and
// json output of metrics, and publish metrics on a schedule.
type InfluxOutput struct {
	kwriter *kafka.Writer
	client  *influxdb2.Client
	config  *InfluxOutputConfig
	// Used for testing with a stable timestamp.
	OverrideTimestamp time.Time
}

// Creates a new influx output controller.
func NewInfluxOutput() *InfluxOutput {
	i := new(InfluxOutput)
	// Reload the config.
	i.Reload()

	return i
}

// Reloads the configuration.
func (i *InfluxOutput) Reload() {
	// Update config state.
	i.config = &app.config.Influx
	i.kwriter = nil
	i.client = nil

	// If kafka output is configured, setup kafka output.
	if len(i.config.KafkaBrokers) != 0 && i.config.KafkaTopic != "" {
		// Configure dialer with configured insecure skip verify.
		dialer := &kafka.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
			TLS:       &tls.Config{InsecureSkipVerify: i.config.KafkaInsecureSkipVerify},
		}

		// If authentication configured, add to dialer.
		if i.config.KafkaUsername != "" {
			dialer.SASLMechanism = plain.Mechanism{
				Username: i.config.KafkaUsername,
				Password: i.config.KafkaPassword,
			}
		}

		// Make the kafka writer.
		i.kwriter = kafka.NewWriter(kafka.WriterConfig{
			Brokers: i.config.KafkaBrokers,
			Topic:   i.config.KafkaTopic,
			Dialer:  dialer,
		})
	}

	// If influx output is configured, setup client.
	if i.config.InfluxServer != "" && i.config.Token != "" && i.config.Org != "" && i.config.Bucket != "" {
		c := influxdb2.NewClient(i.config.InfluxServer, i.config.Token)
		// To allow us to detect rather or not the client is configured, we set the pointer value.
		i.client = &c

	}
}

// Collect metrics from prometheus, then parse into lineprotocol format.
func (i *InfluxOutput) CollectAndLineprotocolFormat() ([]byte, error) {
	res, err := app.registry.Gather()
	if err != nil {
		return nil, err
	}
	return i.LineprotocolFormat(res)
}

// Parse promteheus metrics into lineprotocol format.
func (i *InfluxOutput) LineprotocolFormat(res []*io_prometheus_client.MetricFamily) ([]byte, error) {
	var enc lineprotocol.Encoder

	// Get prefix for transforming prometheus name to influx.
	namePrefix := namespace + "_"
	enc.SetPrecision(lineprotocol.Nanosecond)
	now := time.Now()
	if !i.OverrideTimestamp.IsZero() {
		now = i.OverrideTimestamp
	}

	// Each metric, send to encoder.
	for _, metric := range res {
		// Get name, removing prefix.
		name := metric.GetName()
		if name[0:len(namePrefix)] == namePrefix {
			name = name[len(namePrefix):]
		}
		mtype := metric.GetType()

		// There can be multiple results for a metric, with different tags.
		// We need to make the influx metric on each result.
		for _, m := range metric.GetMetric() {
			// Start new line.
			enc.StartLine(namespace)

			// Add tags.
			enc.AddTag("host", app.config.Hostname)
			for _, l := range m.Label {
				enc.AddTag(l.GetName(), l.GetValue())
			}

			// Depending on type, add field.
			switch mtype {
			case io_prometheus_client.MetricType_COUNTER:
				enc.AddField(name, lineprotocol.MustNewValue(m.Counter.GetValue()))
			case io_prometheus_client.MetricType_GAUGE:
				enc.AddField(name, lineprotocol.MustNewValue(m.Gauge.GetValue()))
			case io_prometheus_client.MetricType_SUMMARY:
				enc.AddField(name, lineprotocol.MustNewValue(m.Summary.GetSampleSum()))
			case io_prometheus_client.MetricType_UNTYPED:
				enc.AddField(name, lineprotocol.MustNewValue(m.Untyped.GetValue()))
			case io_prometheus_client.MetricType_HISTOGRAM:
				enc.AddField(name, lineprotocol.MustNewValue(m.Histogram.GetSampleSum()))
			case io_prometheus_client.MetricType_GAUGE_HISTOGRAM:
				enc.AddField(name, lineprotocol.MustNewValue(m.Histogram.GetSampleSum()))
			}

			// End line for next metric.
			enc.EndLine(now)
		}
	}

	// Check for errors.
	err := enc.Err()
	if err != nil {
		return nil, err
	}

	return enc.Bytes(), nil
}

// Collect metrics from prometheus, then parse into influx json format.
func (i *InfluxOutput) CollectAndJSONFormat() ([]byte, error) {
	res, err := app.registry.Gather()
	if err != nil {
		return nil, err
	}
	return i.JSONFormat(res)
}

// Parse promteheus metrics into influx json format.
func (i *InfluxOutput) JSONFormat(res []*io_prometheus_client.MetricFamily) ([]byte, error) {
	var buff bytes.Buffer

	// Get prefix for transforming prometheus name to influx.
	namePrefix := namespace + "_"
	now := time.Now()
	if !i.OverrideTimestamp.IsZero() {
		now = i.OverrideTimestamp
	}

	// Each metric, send to encoder.
	for _, metric := range res {
		// Get name, removing prefix.
		name := metric.GetName()
		if name[0:len(namePrefix)] == namePrefix {
			name = name[len(namePrefix):]
		}
		mtype := metric.GetType()

		// There can be multiple results for a metric, with different tags.
		// We need to make the influx metric on each result.
		for _, m := range metric.GetMetric() {
			// Create a base dictionary for housing the metric.
			metric := make(map[string]interface{}, 4)

			// Add tags.
			tags := make(map[string]string, len(m.Label)+1)
			tags["host"] = app.config.Hostname
			for _, l := range m.Label {
				tags[l.GetName()] = l.GetValue()
			}
			metric["tags"] = tags

			// Depending on type, add field.
			fields := make(map[string]interface{}, 1)
			switch mtype {
			case io_prometheus_client.MetricType_COUNTER:
				fields[name] = m.Counter.GetValue()
			case io_prometheus_client.MetricType_GAUGE:
				fields[name] = m.Gauge.GetValue()
			case io_prometheus_client.MetricType_SUMMARY:
				fields[name] = m.Summary.GetSampleSum()
			case io_prometheus_client.MetricType_UNTYPED:
				fields[name] = m.Untyped.GetValue()
			case io_prometheus_client.MetricType_HISTOGRAM:
				fields[name] = m.Histogram.GetSampleSum()
			case io_prometheus_client.MetricType_GAUGE_HISTOGRAM:
				fields[name] = m.Histogram.GetSampleSum()
			}
			metric["fields"] = fields

			// Set metric name and ending timestamp.
			metric["name"] = namespace
			metric["timestamp"] = now.UnixNano() / int64(time.Microsecond)

			// Serialize into json.
			serialized, err := json.Marshal(metric)
			if err != nil {
				return nil, err
			}
			// Append new line for parsing into individual metrics.
			serialized = append(serialized, '\n')
			// Write the serialized metric.
			buff.Write(serialized)
		}
	}

	return buff.Bytes(), nil
}

// Returns rather or not output is enabled.
func (i *InfluxOutput) OutputEnabled() bool {
	return (i.kwriter != nil || i.client != nil) && i.config.Frequency != 0
}

// Start the influx output schedule.
func (i *InfluxOutput) Start(ctx context.Context) {
	// If no outputs configured, stop here.
	if !i.OutputEnabled() {
		return
	}

	// Setup schedule.
	ticker := time.NewTicker(i.config.Frequency)
	for {
		select {
		// If schedule tick, gather metrics and send output.
		case <-ticker.C:
			res, err := app.registry.Gather()
			if err != nil {
				log.Println("Error collecting metric for influx output:", err)
				continue
			}

			// If kafka output enabled, send output to kafka.
			if i.kwriter != nil {
				var messages []kafka.Message
				var data []byte

				// Parse metrics based on format.
				if i.config.KafkaOutputFormat == "json" {
					data, err = i.JSONFormat(res)
				} else {
					data, err = i.LineprotocolFormat(res)
				}
				if err != nil {
					log.Println("Error formatting metrics for kafka:", err)
				}

				// Setup parser for new lines.
				r := bytes.NewReader(data)
				scanner := bufio.NewScanner(r)
				scanner.Split(bufio.ScanLines)
				// Set routing key to hostname.
				routingKey := []byte(app.config.Hostname)

				// Scan formatted metrics for each individual metric.
				for scanner.Scan() {
					b := scanner.Bytes()
					// Add back the new line as Kafka output expects it.
					b = append(b, '\n')

					// Add message.
					messages = append(messages, kafka.Message{
						Key:   routingKey,
						Value: b,
					})
				}

				// Write the messages to Kafka.
				err := i.kwriter.WriteMessages(ctx, messages...)
				if err != nil {
					log.Println("Unable to write to Kafka:", err)
				}
			}

			// If influx configured, write metrics to Influx's API.
			if i.client != nil {
				c := *i.client
				writeAPI := c.WriteAPIBlocking(i.config.Org, i.config.Bucket)

				// Parse metrics to lineprotocol.
				data, err := i.LineprotocolFormat(res)
				if err != nil {
					log.Println("Error collecting metric for influx output:", err)
					continue
				}

				// Send all metrics to InfluxDB.
				writeAPI.WriteRecord(ctx, string(data))
			}

		// If the context is done, we need to close out connections.
		case <-ctx.Done():
			if i.kwriter != nil {
				i.kwriter.Close()
			}
			if i.client != nil {
				c := *i.client
				c.Close()
			}
			return
		}
	}
}
