package main

import (
	"log"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Setup global app variable with test config for tests.
func setupInfluxTestApp() {
	app = new(App)
	app.flags = new(Flags)
	app.flags.ConfigPath = "test/test_config.yaml"
	app.ReadConfig()

	// Load exporters.
	app.ldapExporter = NewLDAPExporter()
	app.freeIPAExporter = NewFreeIPAExporter()

	// Add exporters to registry.
	reg := prometheus.NewPedanticRegistry()
	reg.Register(app.ldapExporter)
	reg.Register(app.freeIPAExporter)
	app.registry = reg

	// Setup influx output.
	app.influxOutput = NewInfluxOutput()
	app.influxOutput.OverrideTimestamp, _ = time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
}

// Main Influx test function.
func TestInflux(t *testing.T) {
	// Setup configs.
	setupInfluxTestApp()
	// Run the LDAP test server.
	server := NewLDAPTestServer()
	server.Run()
	// Start http server.
	httpServer := NewFreeIPATestServer()
	httpServer.Run()

	// Get metrics in influx line protocol format.
	data, err := app.influxOutput.CollectAndLineprotocolFormat()
	if err != nil {
		log.Fatalln("Error collecting metrics for telegraf:", err)
	}
	// Check difference from .
	difference, err := FileDiff(string(data), "test/influx.lp")
	if err != nil {
		t.Fatal(err)
	}
	if difference != "" {
		t.Fatalf("Difference from expected result:\n%s", difference)
	}

	// Get metrics in influx json format.
	data, err = app.influxOutput.CollectAndJSONFormat()
	if err != nil {
		log.Fatalln("Error collecting metrics for telegraf:", err)
	}
	// Print the encoded data.
	difference, err = FileDiff(string(data), "test/influx.json")
	if err != nil {
		t.Fatal(err)
	}
	if difference != "" {
		t.Fatalf("Difference from expected result:\n%s", difference)
	}

	// We're done, let's stop serving the test LDAP server.
	server.Stop()
	httpServer.Stop()
}
