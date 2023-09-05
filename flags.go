package main

import (
	"flag"
	"fmt"
	"os"
)

// Flags supplied to cli.
type Flags struct {
	ConfigPath      string
	HTTPBind        string
	HTTPPort        uint
	HTTPMetricsPath string

	TelegrafOutput bool
}

// Parse the supplied flags.
func (a *App) ParseFlags() {
	app.flags = new(Flags)
	flag.Usage = func() {
		fmt.Printf(serviceName + ": " + serviceDescription + ".\n\nUsage:\n")
		flag.PrintDefaults()
	}

	// If version is requested.
	var printVersion bool
	flag.BoolVar(&printVersion, "v", false, "Print version")

	// Override configuration path.
	usage := "Load configuration from `FILE`"
	flag.StringVar(&app.flags.ConfigPath, "config", "", usage)
	flag.StringVar(&app.flags.ConfigPath, "c", "", usage+" (shorthand)")

	// Config overrides for http output.
	flag.StringVar(&app.flags.HTTPBind, "http-bind", "", "Bind address for http server")
	flag.UintVar(&app.flags.HTTPPort, "http-port", 0, "Bind port for http server")
	flag.StringVar(&app.flags.HTTPMetricsPath, "http-metrics-path", "", "Path for pulling prometheus metrics")

	// Rather or not we should output lineprotocol data and exit for telegraf.
	usage = "Output for telegraf execution."
	flag.BoolVar(&app.flags.TelegrafOutput, "telegraf", false, usage)
	flag.BoolVar(&app.flags.TelegrafOutput, "t", false, usage+" (shorthand)")

	// Parse the flags.
	flag.Parse()

	// Print version and exit if requested.
	if printVersion {
		fmt.Println(serviceName + ": " + serviceVersion)
		os.Exit(0)
	}
}
