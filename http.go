package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// The http server output.
type HTTPOutput struct {
	server *http.Server
	mux    *http.ServeMux
	config *HTTPOutputConfig
}

// Make a new http output controller.
func NewHTTPOutput() *HTTPOutput {
	// Create the server.
	s := new(HTTPOutput)
	s.server = &http.Server{}
	// Add update configurations.
	s.Reload()

	return s
}

// Creates the handlers and configures the server.
func (s *HTTPOutput) AddHandlers() {
	// Make a new handler to replace old.
	mux := http.NewServeMux()
	s.mux = mux
	s.server.Handler = mux

	// Register handlers.
	mux.Handle(s.config.MetricsPath, handlers.CombinedLoggingHandler(os.Stdout, promhttp.HandlerFor(app.registry, promhttp.HandlerOpts{})))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Metrics Exporter</title></head>
             <body>
             <h1>Metrics Exporter</h1>
             <p><a href='` + s.config.MetricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
}

// Reload configurations.
func (s *HTTPOutput) Reload() {
	// Update config reference.
	s.config = &app.config.HTTP
	// Update the address.
	s.server.Addr = fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.Port)
	// Update handlers incase the path was re-configured.
	s.AddHandlers()
}

// Returns rather or not output is enabled.
func (s *HTTPOutput) OutputEnabled() bool {
	return s.config.Enabled
}

// Start the HTTP output server.
func (s *HTTPOutput) Start(ctx context.Context) {
	isListening := make(chan bool)
	// Start server.
	go s.StartWithIsListening(ctx, isListening)
	// Allow the http server to initialize.
	<-isListening
}

// Starts the HTTP output server with a listening channel.
func (s *HTTPOutput) StartWithIsListening(ctx context.Context, isListening chan bool) {
	// If http is disabled, stop here.
	if !s.config.Enabled {
		return
	}

	// Watch the background context for when we need to shutdown.
	go func() {
		<-ctx.Done()
		err := s.server.Shutdown(context.Background())
		if err != nil {
			// Error from closing listeners, or context timeout:
			log.Println("Error shutting down http server:", err)
		}
	}()

	// Start the server.
	log.Println("Starting http server:", s.server.Addr)
	l, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		log.Fatal("Listen: ", err)
	}
	// Now notify we are listening.
	isListening <- true
	// Serve http server on the listening port.
	err = s.server.Serve(l)
	if err != nil {
		log.Println("HTTP server failure:", err)
	}
}
