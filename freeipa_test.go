package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/grmrgecko/go-freeipa"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Setup global app variable with test config for tests.
func setupFreeIPATestApp() {
	app = new(App)
	app.flags = new(Flags)
	app.flags.ConfigPath = "test/test_config.yaml"
	app.ReadConfig()
	app.freeIPAExporter = NewFreeIPAExporter()

	// Set ldap address to https port for certificate tests.
	app.config.LDAP.Address = fmt.Sprintf("ldaps://127.0.0.1:%d", httpsPort)
}

// Unused port for testing.
const httpsPort = 8831

type FreeIPATestServer struct {
	server    *http.Server
	mux       *http.ServeMux
	responses map[string]string
}

func NewFreeIPATestServer() *FreeIPATestServer {
	s := new(FreeIPATestServer)

	// Setup handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/ipa/session/login_password", s.handleLogin)
	mux.HandleFunc("/ipa/session/json", s.handleJSON)
	s.mux = mux

	// Setup server config.
	srvAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	s.server = &http.Server{
		Addr:    srvAddr,
		Handler: mux,
	}

	// Method to response file map.
	s.responses = map[string]string{
		"ca_is_enabled": "test/freeipa_ca_is_enabled.json",
		"idrange_find":  "test/freeipa_idrange_find.json",
		"config_show":   "test/freeipa_config_show.json",
		"ca_show":       "test/freeipa_ca_show.json",
	}
	return s
}

// Test login handler.
func (s *FreeIPATestServer) handleLogin(w http.ResponseWriter, req *http.Request) {
	// Logins are form data posts.
	req.ParseForm()

	// Check username/password equals test credentials.
	user := req.Form.Get("user")
	password := req.Form.Get("password")
	if user == app.config.FreeIPA.Username && password == app.config.FreeIPA.Password {
		// Successful login send session cookie.
		cookie := http.Cookie{}
		cookie.Name = "ipa_session"
		cookie.Value = "correct-session-secret"
		cookie.Expires = time.Now().Add(30 * time.Minute)
		cookie.Secure = true
		cookie.HttpOnly = true
		cookie.Path = "/ipa"
		http.SetCookie(w, &cookie)
		w.Header().Set("IPASESSION", "correct-session-secret")
	} else {
		// Invalid login, send rejection.
		w.Header().Set("X-IPA-Rejection-Reason", "invalid-password")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		fmt.Fprintf(w, `<html>
<head>
<title>401 Unauthorized</title>
</head>
<body>
<h1>Invalid Authentication</h1>
<p>
<strong>kinit: Password incorrect while getting initial credentials
</strong>
</p>
</body>
</html>`)
	}
}

// Send JSON file to HTTP request.
func (s *FreeIPATestServer) sendJSONFile(w http.ResponseWriter, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	io.Copy(w, f)
}

// General invalid json error response for testing error handling.
func (s *FreeIPATestServer) sendInvalidJSON(w http.ResponseWriter) {
	s.sendJSONFile(w, "test/freeipa_invalid_json.json")
}

// Handle the json session test request.
func (s *FreeIPATestServer) handleJSON(w http.ResponseWriter, req *http.Request) {
	// If session cookie doesn't exist, something is wrong. Send unauthenticated response.
	cookie, err := req.Cookie("ipa_session")
	if err != nil || cookie.Value != "correct-session-secret" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Generally json response from here.
	w.Header().Set("Content-Type", "application/json")

	// Get the request body and parse it out.
	res := new(freeipa.Request)
	err = json.NewDecoder(req.Body).Decode(res)
	if err != nil {
		// If the json decode fails, send the error.
		s.sendInvalidJSON(w)
		return
	}

	// For testing, we'll consider user_add/user_find as an accepted method, all others will error.
	resFile, ok := s.responses[res.Method]
	if ok {
		s.sendJSONFile(w, resFile)
	} else {
		// Debug output.
		// jsonD, _ := json.Marshal(res)
		// fmt.Println(string(jsonD))

		// An unexpected method received for testing, send error message.
		s.sendInvalidJSON(w)
	}
}

// Run the http server.
func (s *FreeIPATestServer) Run() {
	isListening := make(chan bool)
	// Start server.
	go s.Start(isListening)
	// Allow the http server to initialize.
	<-isListening
}

// Stop the HTTP server.
func (s *FreeIPATestServer) Stop() {
	s.server.Shutdown(context.Background())
}

// Start the HTTP server with a notification channel
// for when the server is listening.
func (s *FreeIPATestServer) Start(isListening chan bool) {
	// Start server.
	l, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		log.Fatal("Listen: ", err)
	}
	// Now notify we are listening.
	isListening <- true
	// Serve http server on the listening port.
	err = s.server.ServeTLS(l, "test/cert.pem", "test/key.pem")
	if err != nil && err != http.ErrServerClosed {
		log.Fatal("Serve: ", err)
	}
}

// Main FreeIPA test function that verifies metrics for FreeIPA and its configurations works.
func TestFreeIPA(t *testing.T) {
	// Setup configs.
	setupFreeIPATestApp()
	// Start http server.
	server := NewFreeIPATestServer()
	server.Run()

	// Open the expected prometheus metrics.
	expected, err := os.Open("test/freeipa.metrics")
	if err != nil {
		t.Fatal("Error opening tests:", err)
	}
	defer expected.Close()

	// Test the LDAP exporter and verify metrics match what's expected.
	err = testutil.CollectAndCompare(app.freeIPAExporter, expected)
	// If results are not as expected, fail test with the error.
	if err != nil {
		t.Fatal("Unexpected metrics returned:", err)
	}

	// Remove all responses to test failures.
	server.responses = nil

	// Open the expected prometheus metrics.
	expected, err = os.Open("test/freeipa_fail.metrics")
	if err != nil {
		t.Fatal("Error opening tests:", err)
	}
	defer expected.Close()

	// Test the LDAP exporter and verify metrics match what's expected.
	err = testutil.CollectAndCompare(app.freeIPAExporter, expected)
	// If results are not as expected, fail test with the error.
	if err != nil {
		t.Fatal("Unexpected metrics returned:", err)
	}

	// Set server to an bad address to test failure to connect.
	app.config.FreeIPA.Host = "bad-address"

	// Open the expected prometheus metrics.
	expected, err = os.Open("test/freeipa_fail_connect.metrics")
	if err != nil {
		t.Fatal("Error opening tests:", err)
	}
	defer expected.Close()

	// Test the LDAP exporter and verify metrics match what's expected.
	err = testutil.CollectAndCompare(app.freeIPAExporter, expected)
	// If results are not as expected, fail test with the error.
	if err != nil {
		t.Fatal("Unexpected metrics returned:", err)
	}

	// Stop as we're done.
	server.Stop()
}
