package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Setup global app variable with test config for tests.
func setupHTTPTestApp() {
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
	app.httpOutput = NewHTTPOutput()
}

// Main HTTP test function.
func TestHTTP(t *testing.T) {
	// Setup configs.
	setupHTTPTestApp()
	// Run the LDAP test server.
	server := NewLDAPTestServer()
	server.Run()
	// Start http server.
	httpServer := NewFreeIPATestServer()
	httpServer.Run()

	// Setup new background context.
	ctx, ctxCancel := context.WithCancel(context.Background())

	// Start http output server.
	app.httpOutput.Start(ctx)

	// Make request for metrics.
	httpConf := &app.config.HTTP
	url := fmt.Sprintf("http://%s:%d%s", httpConf.BindAddr, httpConf.Port, httpConf.MetricsPath)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Perform request.
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	// Close body after we're done.
	defer res.Body.Close()
	// Read all data from the body.
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Check difference.
	difference, err := FileDiff(string(body), "test/http.metrics")
	if err != nil {
		t.Fatal(err)
	}
	if difference != "" {
		t.Fatalf("Difference from expected result:\n%s", difference)
	}

	// We're done, let's stop serving the test LDAP server.
	server.Stop()
	httpServer.Stop()
	ctxCancel()
}
