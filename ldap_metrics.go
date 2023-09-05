package main

import (
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
)

// Creates a metric and appends it to the to the available metrics if enabled.
func (e *LDAPExporter) NewMetric(metricName string, docString string, t prometheus.ValueType, value func() (float64, error)) {
	// If metric is disabled, stop here.
	for _, metric := range e.config.DisabledMetrics {
		if metric == metricName {
			return
		}
	}
	// Create info for this metric.
	info := metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ldap", metricName),
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

// Sets up the exporter with all needed metrics for LDAP.
func (e *LDAPExporter) setupMetrics() {
	// Setup basic metrics.
	e.up = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "ldap_up",
		Help:      "Was the last scrape of FreeIPA successful.",
	})
	e.totalScrapes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ldap_scrapes_total",
		Help:      "Current total HAProxy scrapes.",
	})
	e.totalFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "ldap_failures_total",
		Help:      "Number of errors while scapping metrics.",
	})

	// Info: Number of active users.
	e.NewMetric("user_active_total", "Total number of active users.", prometheus.CounterValue, func() (float64, error) {
		return e.countSubordinates("cn=users,cn=accounts,")
	})

	// Info: Number of stagged users.
	e.NewMetric("user_stage_total", "Total number of staged users.", prometheus.CounterValue, func() (float64, error) {
		return e.countSubordinates("cn=staged users,cn=accounts,cn=provisioning,")
	})

	// Info: Number of inactive, preserved users.
	e.NewMetric("user_preserved_total", "Total number of preserved users.", prometheus.CounterValue, func() (float64, error) {
		return e.countSubordinates("cn=deleted users,cn=accounts,cn=provisioning,")
	})

	// Info: Number of groups.
	e.NewMetric("group_total", "Total number of groups.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=groups,cn=accounts,", "(objectClass=ipausergroup)")
	})

	// Info: Number of hosts.
	e.NewMetric("host_total", "Total number of hosts.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=computers,cn=accounts,", "(fqdn=*)")
	})

	// Info: Number of services.
	e.NewMetric("service_total", "Total number of services.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=services,cn=accounts,", "(krbprincipalname=*)")
	})

	// Info: Number of net groups.
	e.NewMetric("net_group_total", "Total number of net groups.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=ng,cn=alt,", "(ipaUniqueID=*)")
	})

	// Info: Number of host groups.
	e.NewMetric("host_group_total", "Total number of host groups.", prometheus.CounterValue, func() (float64, error) {
		return e.countSubordinates("cn=hostgroups,cn=accounts,")
	})

	// Info: Number of host base access crontrols.
	e.NewMetric("hbac_rule_total", "Total number of HBAC rules.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=hbac,", "(ipaUniqueID=*)")
	})

	// Info: Number of sudo rules.
	e.NewMetric("sudo_rule_total", "Total number of sudo rules.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=sudorules,cn=sudo,", "(ipaUniqueID=*)")
	})

	// Info: Number of DNS zones.
	e.NewMetric("dns_zone_total", "Total number of DNS zones.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntries("cn=dns,", "(|(objectClass=idnszone)(objectClass=idnsforwardzone))")
	})

	// Info: Number of certificates.
	e.NewMetric("certificate_total", "Total number of certificates.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntriesFull(
			"ou=certificateRepository,ou=ca,o=ipaca",
			"(certStatus=*)",
			[]string{"subjectName"},
		)
	})

	// Info: Number of conflicts.
	e.NewMetric("conflicts_total", "Total number of LDAP conflicts.", prometheus.CounterValue, func() (float64, error) {
		return e.countEntriesFull(
			e.config.BaseDN,
			"(|(nsds5ReplConflict=*)(&(objectclass=ldapsubentry)(nsds5ReplConflict=*)))",
			[]string{"nsds5ReplConflict"},
		)
	})

	// Info: Number of ghost replicas.
	e.NewMetric("ghost_replica_total", "Total number of ghost replicas.", prometheus.CounterValue, func() (float64, error) {
		// Setup ghost record request.
		searchRequest := ldap.NewSearchRequest(
			e.config.BaseDN,
			ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectclass=nstombstone)(nsUniqueId=ffffffff-ffffffff-ffffffff-ffffffff))",
			[]string{"nscpentrywsi"},
			nil,
		)

		// Search for ghost records.
		sr, err := e.conn.Search(searchRequest)
		if err != nil {
			return 0, err
		}

		// Check each entry and count replica entries.
		var count float64
		for _, entry := range sr.Entries {
			// If the entry wsi is a replica but doesn't contain ldap, count it as a ghost.
			nscpentrywsi := entry.GetAttributeValue("nscpentrywsi")
			if strings.Contains(nscpentrywsi, "replica ") && !strings.Contains(nscpentrywsi, "ldap") {
				count++
			}
		}

		return count, nil
	})

	// Replica specific metrics.
	e.replicaLastUpdate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ldap", "replica_last_update"),
		"The last time a replica sync occurred.",
		[]string{"replica"},
		nil,
	)
	e.replicaErrorCode = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ldap", "replica_error_code"),
		"Error code from last replica sync.",
		[]string{"replica"},
		nil,
	)
}

// Provide Promethues all descriptions of metrics exported.
func (e *LDAPExporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.metrics {
		ch <- m.Desc
	}
	ch <- e.up.Desc()
	ch <- e.totalScrapes.Desc()
	ch <- e.totalFailures.Desc()
	ch <- e.replicaLastUpdate
	ch <- e.replicaErrorCode
}

// Collects metrics exported and provide values to Prometheus.
func (e *LDAPExporter) Collect(ch chan<- prometheus.Metric) {
	// Protect metrics from concurrent collects.
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Scrape LDAP metrics.
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
}

// Test LDAP and pull metrics.
func (e *LDAPExporter) scrape(ch chan<- prometheus.Metric) float64 {
	// Increment the total number of scrapes.
	e.totalScrapes.Inc()

	// Attempt to connect.
	err := e.connect()
	// If failure, LDAP is down.
	if err != nil {
		log.Println("Error connecting to ldap:", err)
		return 0
	}
	// Disconnect after done scrapping.
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

	// Get replica sync status.
	replicaSyncInfo, err := e.replicaSyncInfo()
	// If error returned, log it.
	if err != nil {
		log.Printf("Error retrieving replica sync info: %s\n", err)
	}
	// Error code parsing.
	statusRx := regexp.MustCompile(`Error \(([0-9-]+)\)`)
	// Update metric for each replica.
	for _, replica := range replicaSyncInfo {
		// Get the last update date UNIX time and send metric.
		ch <- prometheus.MustNewConstMetric(e.replicaLastUpdate, prometheus.GaugeValue, float64(replica.LastUpdateEnd.Unix()), replica.Host)
		// Check if status code can be parsed.
		match := statusRx.FindStringSubmatch(replica.Status)
		if len(match) == 2 {
			// Make status code a float64 as is used by Prometheus. Ignoring errors as none should exist with the regex match being integers only.
			errorCode, _ := strconv.ParseFloat(match[1], 64)
			// Send the status code as a metric.
			ch <- prometheus.MustNewConstMetric(e.replicaErrorCode, prometheus.GaugeValue, errorCode, replica.Host)
		}
	}

	// At this point, we were able to connect, so LDAP is up.
	return 1
}
