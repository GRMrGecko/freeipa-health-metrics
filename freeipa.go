package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grmrgecko/go-freeipa"
	"github.com/prometheus/client_golang/prometheus"
)

// The prometheus exporter for FreeIPA configurations.
type FreeIPAExporter struct {
	config  *FreeIPAConfig
	conn    *freeipa.Client
	mutex   sync.RWMutex
	metrics []metricInfo

	// Basic metrics.
	up                          prometheus.Gauge
	totalScrapes, totalFailures prometheus.Counter
	failedTests                 prometheus.Gauge

	// Caches so we do not have more load than neccessary.
	apiConfigCache       *freeipa.Response
	caCertificateCache   *x509.Certificate
	ipaCertificateCache  []*x509.Certificate
	ldapCertificateCache []*x509.Certificate
	certMongerCertsCache []*CertMongerCerts
}

// Make the FreeIPA exporter.
func NewFreeIPAExporter() *FreeIPAExporter {
	e := new(FreeIPAExporter)
	e.Reload()

	return e
}

// Reload the configurations.
func (e *FreeIPAExporter) Reload() {
	e.config = &app.config.FreeIPA
	e.metrics = nil
	e.setupMetrics()
}

// Get the API configuration from FreeIPA.
func (e *FreeIPAExporter) apiConfig() (*freeipa.Response, error) {
	// If not cached, pull from the API.
	if e.apiConfigCache == nil {
		// Get the configuration from the API.
		params := make(map[string]interface{})
		req := freeipa.NewRequest(
			"config_show",
			[]interface{}{},
			params,
		)
		res, err := e.conn.Do(req)
		if err != nil {
			return nil, err
		}
		e.apiConfigCache = res
	}
	// Return the cache.
	return e.apiConfigCache, nil
}

// Get the FreeIPA CA Certificate.
func (e *FreeIPAExporter) caCert() (*x509.Certificate, error) {
	// If not cached, pull it.
	if e.caCertificateCache == nil {
		// Find the CA certificate in the API.
		params := make(map[string]interface{})
		req := freeipa.NewRequest(
			"ca_show",
			[]interface{}{"ipa"},
			params,
		)
		res, err := e.conn.Do(req)
		if err != nil {
			return nil, err
		}

		// Check if the certificate was returned.
		certS, ok := res.GetString("certificate")
		if !ok {
			return nil, fmt.Errorf("unable to get certificate")
		}

		// Parse the x509 certificate.
		caPEM := "-----BEGIN CERTIFICATE-----\n" + certS + "\n-----END CERTIFICATE-----"
		block, _ := pem.Decode([]byte(caPEM))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		// If we found the certificate, cache it.
		e.caCertificateCache = cert
	}
	// Return the cache.
	return e.caCertificateCache, nil
}

// Get the active certificate on the FreeIPA API http server.
func (e *FreeIPAExporter) ipaCerts() ([]*x509.Certificate, error) {
	// If no cache, pull the certificates.
	if len(e.ipaCertificateCache) == 0 {
		// Determine the proper host name.
		host := e.config.Host
		if !strings.Contains(host, ":") {
			host = host + ":443"
		}

		// In this case, we don't care about security as we're just grabbing certificates.
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
		}
		// Dial the host.
		conn, err := tls.Dial("tcp", host, tlsConf)
		if err != nil {
			return nil, err
		}
		// Close the connection when done.
		defer conn.Close()
		// Get the certificates and cache them.
		certs := conn.ConnectionState().PeerCertificates
		e.ipaCertificateCache = append(e.ipaCertificateCache, certs...)
	}
	// Return cached certificates.
	return e.ipaCertificateCache, nil
}

// Get the active LDAP server certificates.
func (e *FreeIPAExporter) ldapCerts() ([]*x509.Certificate, error) {
	// If not cached, pull them.
	if len(e.ldapCertificateCache) == 0 {
		// Determine the host from the LDAP config.
		addr, err := url.Parse(app.config.LDAP.Address)
		if err != nil {
			return nil, err
		}
		port := addr.Port()
		host := addr.Hostname() + ":" + port
		// If no port defined in the URL, or if the ldaps protocol isn't defined. Use the default port.
		if addr.Scheme != "ldaps" || port == "" {
			host = addr.Hostname() + ":636"
		}

		// In this case, we don't care about security as we're just grabbing certificates.
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
		}
		// Dial the host.
		conn, err := tls.Dial("tcp", host, tlsConf)
		if err != nil {
			return nil, err
		}
		// Close the connection when done.
		defer conn.Close()
		// Get the certificates and cache them.
		certs := conn.ConnectionState().PeerCertificates
		e.ldapCertificateCache = append(e.ldapCertificateCache, certs...)
	}
	// Return cached certificates.
	return e.ldapCertificateCache, nil
}

// Information on the certificates managed by cert monger.
type CertMongerCerts struct {
	RequestID      string
	Status         string
	Stuck          bool
	KeyPairStorage string
	Issuer         string
	Subject        string
	Expires        time.Time
	DNSNames       []string
	Track          bool
	AutoRenew      bool
}

// Pull certificates managed by cert monger.
func (e *FreeIPAExporter) certMongerCerts() ([]*CertMongerCerts, error) {
	// If not cached, pull them.
	if e.certMongerCertsCache == nil {
		var cert *CertMongerCerts
		// Parsing regex for cert monger.
		requestRX := regexp.MustCompile(`Request ID '([A-Za-z0-9]+)':`)
		keyValueRX := regexp.MustCompile(`\s([A-Za-z][A-Za-z- ]+): (.*)$`)

		// Setup the getcert list command.
		cmd := exec.Command(app.config.GetCertBIN, "list")

		// Get the pipes.
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return nil, err
		}

		// Start the command.
		err = cmd.Start()
		if err != nil {
			return nil, err
		}

		// Setup wait group to avoid race condition.
		var wg sync.WaitGroup
		wg.Add(2)

		// Scan the standard output for certificates.
		stdoutScanner := bufio.NewScanner(stdout)
		go func() {
			// Scan each line of the output.
			for stdoutScanner.Scan() {
				line := stdoutScanner.Text()
				// If this is a request line, setup a new certificate.
				if requestRX.MatchString(line) {
					match := requestRX.FindStringSubmatch(line)
					// If match doesn't return expected count, continue.
					if len(match) != 2 {
						continue
					}
					// If the certificate was previously parsed, add it to the cache.
					if cert != nil {
						e.certMongerCertsCache = append(e.certMongerCertsCache, cert)
					}
					// Start a new certificate.
					cert = &CertMongerCerts{
						RequestID: match[1],
					}
				} else if keyValueRX.MatchString(line) {
					// Parse key value entry.
					match := keyValueRX.FindStringSubmatch(line)
					// If match doesn't return expected count, continue.
					if len(match) != 3 {
						continue
					}
					// Check if key is one we're parsing and store the parsed info.
					switch match[1] {
					case "status":
						cert.Status = match[2]
					case "stuck":
						cert.Stuck = match[2] == "yes"
					case "key pair storage":
						cert.KeyPairStorage = match[2]
					case "issuer":
						cert.Issuer = match[2]
					case "subject":
						cert.Subject = match[2]
					case "expires":
						cert.Expires, _ = time.Parse("2006-01-02 15:04:05 MST", match[2])
					case "dns":
						cert.DNSNames = strings.Split(match[2], ",")
					case "track":
						cert.Track = match[2] == "yes"
					case "auto-renew":
						cert.AutoRenew = match[2] == "yes"
					}
				}
			}
			// We're done parsing the standard output.
			wg.Done()
		}()

		// Scan the standard error output and pass to our standard error.
		stderrScanner := bufio.NewScanner(stderr)
		go func() {
			for stderrScanner.Scan() {
				line := stderrScanner.Text()
				fmt.Fprintln(os.Stderr, line)
			}
			wg.Done()
		}()

		// Wait for file reads to finish before waiting on command to finnish to avoid a race condition.
		wg.Wait()

		// Wait for the command to and check if error returned.
		err = cmd.Wait()
		if err != nil {
			return nil, err
		}

		// If a certificate was parsed, add it to the cache.
		if cert != nil {
			e.certMongerCertsCache = append(e.certMongerCertsCache, cert)
		}
	}
	// Return cached list.
	return e.certMongerCertsCache, nil
}

// Connect to the FreeIPA API.
func (e *FreeIPAExporter) connect() error {
	var err error

	// Setup TLS configurations.
	tlsConifg := tls.Config{InsecureSkipVerify: e.config.InsecureSkipVerify}
	// Load CA certificates if configured.
	if e.config.CACertificate != "" {
		caCert, err := os.ReadFile(e.config.CACertificate)
		if err != nil {
			log.Println("Error reading CA certificate:", err)
		} else {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConifg.RootCAs = caCertPool
		}
	}

	// Update the transport config with TLS config.
	transportConfig := &http.Transport{
		TLSClientConfig: &tlsConifg,
	}

	// If we're logging in with plain authentication, do so.
	if e.config.Username != "" && e.config.Password != "" {
		e.conn, err = freeipa.Connect(e.config.Host, transportConfig, e.config.Username, e.config.Password)
		return err
	}

	// Plain authentication wasn't used, so now we try logging in with Kerberos authentication.
	// Read the keytab for kerberos.
	krb5KtFd, err := os.Open(app.config.Krb5KeytabPath)
	if err != nil {
		return err
	}
	// Close keytab after we're done.
	defer krb5KtFd.Close()

	// Open the kerberos config file.
	krb5Fd, err := os.Open(app.config.Krb5ConfigPath)
	if err != nil {
		return err
	}
	// Close the config file afte we're done.
	defer krb5Fd.Close()

	// Setup the kerberos connection options.
	krb5ConnectOption := &freeipa.KerberosConnectOptions{
		Krb5ConfigReader: krb5Fd,
		KeytabReader:     krb5KtFd,
		User:             e.config.Krb5Principal,
		Realm:            e.config.Krb5Realm,
	}

	// Attempt to connect with kerberos.
	e.conn, err = freeipa.ConnectWithKerberos(e.config.Host, transportConfig, krb5ConnectOption)
	return err
}

// Disconnect from the API.
func (e *FreeIPAExporter) disconnect() {
	if e.conn != nil {
		e.conn = nil
		// Clear caches.
		e.apiConfigCache = nil
		e.caCertificateCache = nil
		e.ipaCertificateCache = nil
		e.ldapCertificateCache = nil
		e.certMongerCertsCache = nil
	}
}
