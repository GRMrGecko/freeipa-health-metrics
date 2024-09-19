package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
)

// Basic application info.
const (
	serviceName        = "freeipa-health-metrics"
	serviceDescription = "Provides metrics of FreeIPA's health"
	serviceVersion     = "0.4"
	namespace          = "freeipa"
)

// The standard prometheus metric info structure which includes the description, type,
// and a sub function to collect the value.
type metricInfo struct {
	Desc  *prometheus.Desc
	Type  prometheus.ValueType
	Value func() (float64, error)
}

// The global application structure used to access diffent state structures and configuration.
type App struct {
	flags           *Flags
	config          *Config
	registry        *prometheus.Registry
	ldapExporter    *LDAPExporter
	freeIPAExporter *FreeIPAExporter
	httpOutput      *HTTPOutput
	influxOutput    *InfluxOutput
}

// Global variable for the app structure to make it easy to get the active state.
var app *App

// The main program function/run loop.
func main() {
	// Setup the app structure.
	app = new(App)
	app.ParseFlags()
	app.ReadConfig()

	// Load exporters.
	app.ldapExporter = NewLDAPExporter()
	app.freeIPAExporter = NewFreeIPAExporter()

	// Add exporters to registry.
	reg := prometheus.NewPedanticRegistry()
	reg.Register(app.ldapExporter)
	reg.Register(app.freeIPAExporter)
	app.registry = reg

	// Load outputs.
	app.httpOutput = NewHTTPOutput()
	app.influxOutput = NewInfluxOutput()

	// If requested telegraf output.
	if app.flags.TelegrafOutput {
		// Get metrics in influx line protocol format.
		data, err := app.influxOutput.CollectAndLineprotocolFormat()
		if err != nil {
			log.Fatalln("Error collecting metrics for telegraf:", err)
		}
		// Print the encoded data.
		fmt.Println(string(data))
		return
	}

	// Setup context with cancellation function to allow background services to gracefully stop.
	ctx, ctxCancel := context.WithCancel(context.Background())

	// Start http output server.
	go app.httpOutput.Start(ctx)

	// Start the influx output schedule.
	go app.influxOutput.Start(ctx)

	// Monitor common signals.
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Run program until cancelled.
	for sig := range c {
		switch sig {
		// If hangup signal receivied, reload the configurations.
		case syscall.SIGHUP:
			log.Println("Reloading configurations")
			// Capture old config for checks.
			oldConfig := app.config
			// Get prior state of influx output.
			influxOutputWasEnabled := app.influxOutput.OutputEnabled()

			// Read new config.
			app.ReadConfig()

			// Reload config on each exporter and output.
			app.ldapExporter.Reload()
			app.freeIPAExporter.Reload()
			app.httpOutput.Reload()
			app.influxOutput.Reload()

			// Check if httpd server config changes require restart.
			httpNeedsRestart := oldConfig.HTTP.BindAddr != app.config.HTTP.BindAddr || oldConfig.HTTP.Port != app.config.HTTP.Port || oldConfig.HTTP.Enabled != app.config.HTTP.Enabled
			// Check if influx output config changes require restart.
			influxNeedsRestart := app.influxOutput.OutputEnabled() != influxOutputWasEnabled || oldConfig.Influx.Frequency != app.config.Influx.Frequency

			// If either output service requires restart, restart both.
			if httpNeedsRestart || influxNeedsRestart {
				// Cancel prior background context.
				ctxCancel()

				// Setup new background context.
				ctx, ctxCancel = context.WithCancel(context.Background())

				// Start http output server.
				go app.httpOutput.Start(ctx)

				// Start the influx output schedule.
				go app.influxOutput.Start(ctx)
			}

		// The default signal is either termination or interruption, so cancel the
		// background context and exit this program.
		default:
			ctxCancel()
			return
		}
	}
}
