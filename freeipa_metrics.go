package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/grmrgecko/go-freeipa"
	UNIXAccounts "github.com/grmrgecko/go-unixaccounts"
	"github.com/prometheus/client_golang/prometheus"
)

// Creates a metric and appends it to the to the available metrics if enabled.
func (e *FreeIPAExporter) NewMetric(metricName string, docString string, t prometheus.ValueType, value func() (float64, error)) {
	// If metric is disabled, stop here.
	for _, metric := range e.config.DisabledMetrics {
		if metric == metricName {
			return
		}
	}
	// Create info for this metric.
	info := metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "config", metricName),
			docString,
			nil,
			nil,
		),
		Type:  t,
		Value: value,
	}
	// Add metric to list.
	e.metrics = append(e.metrics, info)
}

// Sets up the exporter with all needed metrics for FreeIPA.
func (e *FreeIPAExporter) setupMetrics() {
	// Setup basic metrics.
	e.up = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "up",
		Help:      "Was the last scrape of FreeIPA successful.",
	})
	e.totalScrapes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "scrapes_total",
		Help:      "Current total HAProxy scrapes.",
	})
	e.totalFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "failures_total",
		Help:      "Number of errors while scapping metrics.",
	})
	e.failedTests = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "freeipa_failed_tests",
		Help:      "Number of failed tests in the most recent scrape.",
	})

	// Test: Ensure that kerberos authentication works with kinit and klist.
	e.NewMetric("krb5_auth", "Kerberos can authenticate.", prometheus.GaugeValue, func() (float64, error) {
		// Specific cache file for tokens to ensure we're not succeeding due to previous check.
		krb5CacheFile := fmt.Sprintf("/tmp/krb5_cache_%d", rand.Int())
		// Remove file when test is done.
		defer os.Remove(krb5CacheFile)
		// Get pricipal with realm for authentication.
		krb5Principal := e.config.Krb5Principal + "@" + e.config.Krb5Realm

		// Authenticate with kinit.
		cmd := exec.Command(app.config.KInitBin, "-kt", app.config.Krb5KeytabPath, "-c", krb5CacheFile, krb5Principal)

		// Run kinit, which will error if exit code is not 0 as expected.
		_, err := cmd.Output()
		if err != nil {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, err
		}

		// Verify the cache file contains the token with klist.
		cmd = exec.Command(app.config.KListBin, "-c", krb5CacheFile)

		// Run klist, which will error if exit code is not 0 as expected.
		_, err = cmd.Output()
		if err != nil {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, err
		}

		// Both tests suceeded, return 1.
		return 1, nil
	})

	// Test: The number of workers configured for the directory server should equal number of cores.
	e.NewMetric("krb5_workers", "Workers match processors.", prometheus.GaugeValue, func() (float64, error) {
		// Open the kerberos server configuration file.
		f, err := os.Open(app.config.Krb5SysConfigPath)
		if err != nil {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, err
		}
		// Close file after test is done.
		defer f.Close()

		// Scan the file for each line.
		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)

		// Default to zero workers.
		workers := 0
		// The workers are defined as `-w WORKERS` in the cli arguments.
		rxWorkers := regexp.MustCompile(`=.*-w\s*([0-9]+)`)
		// Scan each line for the number of workers.
		for scanner.Scan() {
			line := scanner.Text()
			// If line is the arguments config, parse it.
			if strings.HasPrefix(line, "KRB5KDC_ARGS") {
				// Parse line for number of workers.
				match := rxWorkers.FindStringSubmatch(line)
				if len(match) == 2 {
					workers, _ = strconv.Atoi(match[1])
				}
			}
		}

		// Check number of workers configured against number of CPU cores.
		if workers != runtime.NumCPU() {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, fmt.Errorf("number of workers does not match CPU cores")
		}

		// If successful, return 1.
		return 1, nil
	})

	/*
		Test: The DNA range specify the starting user ID,
		there needs to be at least one master with a range set.
	*/
	e.NewMetric("dna_range", "DNA range is defined.", prometheus.GaugeValue, func() (float64, error) {
		// Pull from FreeIPA API all DNA ranges found.
		params := make(map[string]interface{})
		req := freeipa.NewRequest(
			"idrange_find",
			[]interface{}{""},
			params,
		)
		res, err := e.conn.Do(req)
		if err != nil {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, err
		}

		// If no DNA ranges found, fail.
		if res.Result.Count == 0 {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, fmt.Errorf("no DNA ID range found")
		}

		// Success, return 1.
		return 1, nil
	})

	/*
	   Test: This ensures that groups specified in the config have specific members.
	   By default, we define this check to verify the ipaapi user is a member
	   of the apache group. This is critical for security and access to cache.
	*/
	e.NewMetric("group_members", "Group members are as expected.", prometheus.GaugeValue, func() (float64, error) {
		// Get UNIX account list.
		accounts, err := UNIXAccounts.NewUNIXAccounts()
		if err != nil {
			e.failedTests.Inc()
			return 0, err
		}

		// Check each ground member configuration.
		for _, check := range e.config.GroupMembers {
			// Find the group that matches the name configured.
			group := accounts.GroupWithName(check.Name)
			// If group not found, fail.
			if group == nil {
				// As this is a test, add to the tests failed counter.
				e.failedTests.Inc()
				return 0, fmt.Errorf("unable to find group with name: %s", check.Name)
			}

			// Get all users in this group.
			users := accounts.UsersInGroup(group)
			// Check each member configured to verify they are a group memebr.
			for _, member := range check.Members {
				// Check all users in this group to see if they are this member.
				userIsMember := false
				for _, user := range users {
					if user.Name == member {
						userIsMember = true
					}
				}
				// If member isn't a user in the group, fail.
				if !userIsMember {
					// As this is a test, add to the tests failed counter.
					e.failedTests.Inc()
					return 0, fmt.Errorf("user %s should be a member of %s", member, check.Name)
				}
			}
		}

		// If we reached this point, no test failed.
		return 1, nil
	})

	// Test: Confirm the shared secret between tomcat and Apache match.
	e.NewMetric("proxy_secret", "Proxy secret is configured.", prometheus.GaugeValue, func() (float64, error) {
		// Open the tomcat server configuration file.
		xmlF, err := os.Open(app.config.PKITomcatServerXML)
		if err != nil {
			e.failedTests.Inc()
			return 0, err
		}
		// Close config at end of test.
		defer xmlF.Close()

		// Query XML for the AJP connector configuration.
		p, err := xmlquery.CreateStreamParser(xmlF, `//Connector[@protocol="AJP/1.3"]`)
		if err != nil {
			e.failedTests.Inc()
			return 0, err
		}
		// Variable to store found secrets.
		var foundSecrets []string

		// Pull the first connector match if possible.
		n, err := p.Read()
		// If EOF reached, no connectors are defined.
		if err == io.EOF {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, fmt.Errorf("no AJP/1.3 connectors defined")
		}
		// Other erros are general.
		if err != nil {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, err
		}

		// Get the secret attribute from the connector. This only may be configured on older installs.
		secret := n.SelectAttr("secret")
		if secret != "" {
			foundSecrets = append(foundSecrets, secret)
		}
		// Get the required secret which is the newer attribute name.
		secret = n.SelectAttr("requiredSecret")
		if secret != "" {
			foundSecrets = append(foundSecrets, secret)
		}

		// If there are more than one secret, check if they both match.
		if len(foundSecrets) > 1 {
			if foundSecrets[0] != foundSecrets[1] {
				// As this is a test, add to the tests failed counter.
				e.failedTests.Inc()
				return 0, fmt.Errorf("the AJP secrets do not match")
			}
		}
		// If no secrets were found, fail.
		if len(foundSecrets) == 0 {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, fmt.Errorf("no AJP secrets found")
		}

		// Open the Apache HTTPD proxy configuration file.
		f, err := os.Open(app.config.HTTPDPKIProxyConf)
		if err != nil {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, err
		}
		// Close this config file at end of test.
		defer f.Close()

		// Create a new line scanner for the httpd configuration file.
		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)
		// Parse regex for expected configuration.
		proxyRx := regexp.MustCompile(`\s+ProxyPassMatch ajp://localhost:8009 secret=(\w+)$`)
		// List of found secrets.
		var foundProxySecrets []string

		// Scan each line of the config for secrets.
		for scanner.Scan() {
			line := scanner.Text()
			// If line matches a secret, get the secret.
			if proxyRx.MatchString(line) {
				match := proxyRx.FindStringSubmatch(line)
				if len(match) == 2 {
					// Add secret to the list.
					foundProxySecrets = append(foundProxySecrets, match[1])
				}
			}
		}

		// If no secrets found in HTTPD config, fail.
		if len(foundProxySecrets) == 0 {
			// As this is a test, add to the tests failed counter.
			e.failedTests.Inc()
			return 0, fmt.Errorf("no AJP proxy secrets found")
		}

		// Check each found proxy secret against the tomcat secrets.
		for _, secret := range foundProxySecrets {
			foundMatch := false
			for _, xmlSecret := range foundSecrets {
				if secret == xmlSecret {
					foundMatch = true
				}
			}
			// If no match found, fail.
			if !foundMatch {
				// As this is a test, add to the tests failed counter.
				e.failedTests.Inc()
				return 0, fmt.Errorf("the AJP secrets configured do not match between tomcat and apache")
			}
		}

		// At this point, the test succeeded.
		return 1, nil
	})

	// Info: Is this server the renewal master?
	e.NewMetric("renewal_master", "This server is the renewal master.", prometheus.GaugeValue, func() (float64, error) {
		// Get the FreeIPA config.
		config, err := e.apiConfig()
		if err != nil {
			return 0, err
		}

		// Get the configured renewal master.
		masterServer, _ := config.GetString("ca_renewal_master_server")
		// This is a renewal master if the configured hostname matches.
		if masterServer != app.config.Hostname {
			return 0, nil
		}

		return 1, nil
	})

	// Info: Did the IPA CA sign the FreeIPA API certificate?
	e.NewMetric("ipa_ca_issued_cert", "The FreeIPA API was issued a certificate by the CA cert.", prometheus.GaugeValue, func() (float64, error) {
		// Get the CA certificate.
		caCert, err := e.caCert()
		if err != nil {
			return 0, err
		}

		// Get the FreeIPA API certificate.
		ipaCerts, err := e.ipaCerts()
		if err != nil {
			return 0, err
		}

		// Check each certificate returned by the API against the CA certificate.
		countSuccess := 0
		for _, cert := range ipaCerts {
			// Ignore the CA certificates.
			if cert.IsCA {
				continue
			}
			// If the signature is signed by the CA certificate, add to the successes.
			err := cert.CheckSignatureFrom(caCert)
			if err == nil {
				countSuccess++
			}
		}
		// If no successful signature checks, there are no certificates signed by the CA certificate.
		if countSuccess == 0 {
			return 0, fmt.Errorf("certificates are not issued by ca certificate")
		}

		// At this point, a certificate was found to be signed by the CA certificate.
		return 1, nil
	})

	// Info: Is the FreeIPA API certificate in certmonger for autorenew?
	e.NewMetric("ipa_cert_auto_renew", "The FreeIPA API certificate is managed and set to auto renew.", prometheus.GaugeValue, func() (float64, error) {
		// Get certificates managed by cert monger.
		certsFound, err := e.certMongerCerts()
		if err != nil {
			return 0, err
		}

		// Get info about the httpd certificate.
		var httpSubject string
		autoRenew := false
		for _, cert := range certsFound {
			// If certificate storage path is in the httpd path, this is the httpd certificate.
			if strings.Contains(cert.KeyPairStorage, "httpd") {
				httpSubject = cert.Subject
				autoRenew = cert.Status == "MONITORING" && cert.AutoRenew && !cert.Stuck && cert.Track
			}
		}

		// Get the FreeIPA API certificates.
		ipaCerts, err := e.ipaCerts()
		if err != nil {
			return 0, err
		}

		// Check if the certificate currently returned by FreeIPA is the one found in cert monger.
		foundCerts := 0
		for _, cert := range ipaCerts {
			// If is an CA certificate, skip.
			if cert.IsCA {
				continue
			}
			thisSubject := cert.Subject.String()
			// OpenSSL seems to escape the comma.
			thisSubject = strings.ReplaceAll(thisSubject, "\\,", ",")
			// If subject matches, this is the certificate in certmonger..
			if thisSubject == httpSubject {
				foundCerts++
			}
		}

		// If no certificates found, return error.
		if foundCerts == 0 {
			return 0, fmt.Errorf("unable to determine if http cert is auto renew")
		}

		// If not auto renew, return 0.
		if !autoRenew {
			return 0, nil
		}

		// At this point, the certificate was found and has been determined to be autorenew.
		return 1, nil
	})

	// Info: The unix timestamp of the earliest FreeIPA API certificate expiry date.
	e.NewMetric("ipa_earliest_cert_expiry", "The earliest certificate expiry date for FreeIPA API.", prometheus.GaugeValue, func() (float64, error) {
		// Get FreeIPA API certificates.
		ipaCerts, err := e.ipaCerts()
		if err != nil {
			return 0, err
		}

		// Find the earliest expiry date.
		earliest := time.Time{}
		for _, cert := range ipaCerts {
			// If this is before the previously found earliest, update.
			if earliest.IsZero() || (cert.NotAfter.Before(earliest) && !cert.NotAfter.IsZero()) {
				earliest = cert.NotAfter
			}
		}
		// If the earliest date found is zero, we did not find any expiry dates.
		if earliest.IsZero() {
			return 0, fmt.Errorf("unable to find earliest cert")
		}

		// Return the earliest date in unix time format.
		return float64(earliest.Unix()), nil
	})

	// Info: Did the IPA CA sign the LDAP certificate?
	e.NewMetric("ipa_ca_issued_ldap_cert", "The LDAP cert was issued a certificate by the CA cert.", prometheus.GaugeValue, func() (float64, error) {
		// Get the CA certificate.
		caCert, err := e.caCert()
		if err != nil {
			return 0, err
		}

		// Get the LDAP certificates.
		ldapCerts, err := e.ldapCerts()
		if err != nil {
			return 0, err
		}

		// Check each certificate.
		countSuccess := 0
		for _, cert := range ldapCerts {
			// If this is a CA certificate, ignore.
			if cert.IsCA {
				continue
			}
			// If the signature was signed by the CA certificate, add to the count.
			err := cert.CheckSignatureFrom(caCert)
			if err == nil {
				countSuccess++
			}
		}
		// If no successful signature checks, there are no certificates signed by the CA certificate.
		if countSuccess == 0 {
			return 0, fmt.Errorf("certificates are not issued by ca certificate")
		}

		// At this point, a certificate was found to be signed by the CA certificate.
		return 1, nil
	})

	// Info: Is the LDAP certificate in certmonger for autorenew?
	e.NewMetric("ldap_cert_auto_renew", "The LDAP certificate is managed and set to auto renew.", prometheus.GaugeValue, func() (float64, error) {
		// Get the certificates managed by cert monger.
		certsFound, err := e.certMongerCerts()
		if err != nil {
			return 0, err
		}

		// Find info about the LDAP certificate in cert monger.
		var httpSubject string
		autoRenew := false
		for _, cert := range certsFound {
			// If the storage path is in the dirsrv folder, this is an LDAP certificate.
			if strings.Contains(cert.KeyPairStorage, "dirsrv") {
				httpSubject = cert.Subject
				autoRenew = cert.Status == "MONITORING" && cert.AutoRenew && !cert.Stuck && cert.Track
			}
		}

		// Get the LDAP certificates.
		ldapCerts, err := e.ldapCerts()
		if err != nil {
			return 0, err
		}

		// Check each LDAP certificate to see if it matches the one in cert monger.
		foundCerts := 0
		for _, cert := range ldapCerts {
			// If CA certificate, ignore.
			if cert.IsCA {
				continue
			}
			thisSubject := cert.Subject.String()
			// OpenSSL seems to escape the comma.
			thisSubject = strings.ReplaceAll(thisSubject, "\\,", ",")
			// If this certificate matches the cert monger certificate.
			if thisSubject == httpSubject {
				foundCerts++
			}
		}

		// If no certificates found, return error.
		if foundCerts == 0 {
			return 0, fmt.Errorf("unable to determine if LDAP cert is auto renew")
		}

		// If not auto renew, return 0.
		if !autoRenew {
			return 0, nil
		}

		// At this point, the certificate was found and has been determined to be autorenew.
		return 1, nil
	})

	// Info: The unix timestamp of the earliest LDAP certificate expiry date.
	e.NewMetric("ldap_earliest_cert_expiry", "The earliest certificate expiry date for LDAP.", prometheus.GaugeValue, func() (float64, error) {
		// Get the LDAP certificates.
		ldapCerts, err := e.ldapCerts()
		if err != nil {
			return 0, err
		}

		// Find the earliest expiry date.
		earliest := time.Time{}
		for _, cert := range ldapCerts {
			// If this is before the previously found earliest, update.
			if earliest.IsZero() || (cert.NotAfter.Before(earliest) && !cert.NotAfter.IsZero()) {
				earliest = cert.NotAfter
			}
		}

		// If the earliest date found is zero, we did not find any expiry dates.
		if earliest.IsZero() {
			return 0, fmt.Errorf("unable to find earliest cert")
		}

		// Return the earliest date in unix time format.
		return float64(earliest.Unix()), nil
	})
}

// Provide Promethues all descriptions of metrics exported.
func (e *FreeIPAExporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.metrics {
		ch <- m.Desc
	}
	ch <- e.up.Desc()
	ch <- e.totalScrapes.Desc()
	ch <- e.totalFailures.Desc()
	ch <- e.failedTests.Desc()
}

// Collects metrics exported and provide values to Prometheus.
func (e *FreeIPAExporter) Collect(ch chan<- prometheus.Metric) {
	// Protect metrics from concurrent collects.
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Scrape FreeIPA metrics.
	up := e.scrape(ch)
	// Update the up status.
	e.up.Set(up)
	// If not up, count as a failed scrape.
	if up == 0 {
		e.totalFailures.Inc()
	}

	// Send basic metrics.
	ch <- e.up
	ch <- e.totalScrapes
	ch <- e.totalFailures
	ch <- e.failedTests
}

// Test FreeIPA and pull metrics.
func (e *FreeIPAExporter) scrape(ch chan<- prometheus.Metric) float64 {
	// Reset the number of failed tests.
	e.failedTests.Set(0)
	// Increment the total number of scrapes.
	e.totalScrapes.Inc()

	// Attempt to connect to the FreeIPA API.
	err := e.connect()
	// If failure connecting, FreeIPA API is not up.
	if err != nil {
		log.Println("Error connecting to FreeIPA API:", err)
		return 0
	}
	// Disconnect after we're done scrapping information.
	defer e.disconnect()

	// Update data for each metric.
	for _, m := range e.metrics {
		// Get the value of the metric.
		value, err := m.Value()
		// If an error occurred getting the value, log it for debug.
		if err != nil {
			log.Printf("Error retrieving value for metric %s: %s\n", m.Desc.String(), err)
		}

		// Update the value.
		ch <- prometheus.MustNewConstMetric(m.Desc, m.Type, value)
	}

	// The FreeIPA API server is up.
	return 1
}
