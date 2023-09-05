package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus exporter for LDAP metrics.
type LDAPExporter struct {
	config  *LDAPConfig
	conn    *ldap.Conn
	mutex   sync.RWMutex
	metrics []metricInfo

	// Basic metrics.
	up                          prometheus.Gauge
	totalScrapes, totalFailures prometheus.Counter

	// Replica metrics and cache.
	replicaLastUpdate    *prometheus.Desc
	replicaErrorCode     *prometheus.Desc
	replicaSyncInfoCache []*ReplicaSyncInfo
}

// Make the LDAP exporter.
func NewLDAPExporter() *LDAPExporter {
	e := new(LDAPExporter)
	e.Reload()

	return e
}

// Reload the configurations.
func (e *LDAPExporter) Reload() {
	e.config = &app.config.LDAP
	e.metrics = nil
	e.setupMetrics()
}

// Connect to the LDAP server.
func (e *LDAPExporter) connect() error {
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

	// Depending on connect method, connect to the LDAP server.
	if e.config.ConnectMethod == LDAPMethodSecure {
		e.conn, err = ldap.DialURL(e.config.Address, ldap.DialWithTLSConfig(&tlsConifg))
	} else if e.config.ConnectMethod == LDAPMethodStartTLS {
		e.conn, err = ldap.DialURL(e.config.Address)
		if err != nil {
			return err
		}
		err = e.conn.StartTLS(&tlsConifg)
	} else {
		e.conn, err = ldap.DialURL(e.config.Address)
	}
	// If error, may be with StartTLS, so disconnect.
	if err != nil {
		e.disconnect()
		return err
	}

	// Attempt to authenticate.
	if e.config.BindPassword == "" {
		err = e.conn.UnauthenticatedBind(e.config.BindDN)
	} else {
		err = e.conn.Bind(e.config.BindDN, e.config.BindPassword)
	}
	// If error in authenticating, disconnect.
	if err != nil {
		e.disconnect()
	}
	// Return error if occurred or nil if no error.
	return err
}

// Disconnect from the LDAP server.
func (e *LDAPExporter) disconnect() {
	if e.conn != nil {
		// Close the connection.
		e.conn.Close()
		e.conn = nil
		// Clear the cache.
		e.replicaSyncInfoCache = nil
	}
}

// Helper function to pull the `numSubordinates` attribute from LDAP.
// This attribute is helpful in getting a count of records under a tree,
// which may be user accounts or otherwise.
func (e *LDAPExporter) countSubordinates(baseDN string) (float64, error) {
	// Setup request for the `numSubordinates` attribute.
	searchRequest := ldap.NewSearchRequest(
		baseDN+e.config.BaseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"numSubordinates"},
		nil,
	)

	// Search for the records.
	sr, err := e.conn.Search(searchRequest)
	if err != nil {
		return 0, err
	}

	// Get the string of the entry.
	var count string
	for _, entry := range sr.Entries {
		count = entry.GetAttributeValue("numSubordinates")
	}

	// Parse received string as float64.
	return strconv.ParseFloat(count, 64)
}

// Short hand to append the BaseDN and request only the `dn` entry, as is all that is needed for most metrics.
// The countEntriesFull function just counts each sub entry from a record.
func (e *LDAPExporter) countEntries(baseDN, filter string) (float64, error) {
	return e.countEntriesFull(baseDN+e.config.BaseDN, filter, []string{"dn"})
}

// Count sub entries of a record and return the count.
func (e *LDAPExporter) countEntriesFull(baseDN, filter string, attributes []string) (float64, error) {
	// Setup request.
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, e.config.SearchSizeLimit, false,
		filter,
		attributes,
		nil,
	)

	// Perform the search.
	sr, err := e.conn.SearchWithPaging(searchRequest, uint32(e.config.SearchSizeLimit))

	// If no such object error returned, return count of 0 with no error.
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return 0, nil
	}

	// Other errors, return the error code.
	if err != nil {
		return 0, err
	}

	// Return a float64 representation of the number of entries found.
	return float64(len(sr.Entries)), nil
}

// The standard date format used in LDAP records.
const LDAPGeneralizedTimeFormat = "20060102150405Z"

// Information on sync status to a replica.
type ReplicaSyncInfo struct {
	Host            string
	LastUpdateStart time.Time
	LastUpdateEnd   time.Time
	Status          string
}

// Pull and return replica sync information.
func (e *LDAPExporter) replicaSyncInfo() ([]*ReplicaSyncInfo, error) {
	// If not cached, pull it.
	if len(e.replicaSyncInfoCache) == 0 {
		// Combined dictionary of available peers, both masters and replicas, with their config.
		peers := make(map[string][]string)

		// Get the master servers.
		masterRequest := ldap.NewSearchRequest(
			"cn=masters,cn=ipa,cn=etc,"+e.config.BaseDN,
			ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{},
			nil,
		)
		sr, err := e.conn.Search(masterRequest)
		if err != nil {
			return nil, err
		}
		// For each master replica, add them with a simple "master" config.
		for _, entry := range sr.Entries {
			cn := entry.GetAttributeValue("cn")
			peers[cn] = []string{"master", ""}
		}

		// Get replicas.
		replicaRequest := ldap.NewSearchRequest(
			"cn=replicas,cn=ipa,cn=etc,"+e.config.BaseDN,
			ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{},
			nil,
		)
		sr, err = e.conn.Search(replicaRequest)
		if err != nil {
			return nil, err
		}
		// Add each replica with their configs.
		for _, entry := range sr.Entries {
			cn := entry.GetAttributeValue("cn")
			configString := entry.GetAttributeValue("ipaConfigString")
			peers[cn] = strings.Split(configString, ":")
		}

		// Determine if this host is an existing peer and rather or not there
		// is a windows sync peer configuration.
		isReplica := false
		winsyncPeer := ""
		for k, v := range peers {
			// If configured hostname matches this peer, this is a replica.
			if app.config.Hostname == k {
				isReplica = true
				// If the config key is winsync, note the peer for finding the replication agreements.
				if len(v) == 2 && v[0] == "winsync" {
					winsyncPeer = v[1]
				}
			}
		}

		// If this host isn't a replica, there is no syncing to/from other nodes. Fail here.
		if !isReplica {
			return nil, fmt.Errorf("this is not an replica/master node")
		}

		if winsyncPeer != "" {
			// Find replication agreements for winsync.
			suffix := ldap.EscapeDN(e.config.BaseDN)
			dn := "cn=meTo" + ldap.EscapeDN(app.config.Hostname) + "cn=replica,cn=" + suffix + ",cn=mapping tree,cn=config"
			winsyncRequest := ldap.NewSearchRequest(
				dn,
				ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
				"(objectclass=nsDSWindowsReplicationAgreement)",
				[]string{},
				nil,
			)
			sr, err = e.conn.Search(winsyncRequest)
			if err != nil {
				return nil, err
			}
		} else {
			// Find replication agreements for regular ds389 replications.
			filter := "(|(&(objectclass=nsds5ReplicationAgreement)(nsDS5ReplicaRoot=" + e.config.BaseDN + "))(objectclass=nsDSWindowsReplicationAgreement))"

			winsyncRequest := ldap.NewSearchRequest(
				"cn=mapping tree,cn=config",
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				filter,
				[]string{},
				nil,
			)
			sr, err = e.conn.Search(winsyncRequest)
			if err != nil {
				return nil, err
			}
		}

		// For each replication agreement, parse replica info.
		for _, entry := range sr.Entries {
			// Parse the last update start.
			startTime, err := time.Parse(LDAPGeneralizedTimeFormat, entry.GetAttributeValue("nsds5replicaLastUpdateStart"))
			if err != nil {
				return nil, err
			}
			// Parse the last update end.
			endTime, err := time.Parse(LDAPGeneralizedTimeFormat, entry.GetAttributeValue("nsds5replicaLastUpdateEnd"))
			if err != nil {
				return nil, err
			}
			// Create the replica info.
			replica := &ReplicaSyncInfo{
				Host:            entry.GetAttributeValue("nsDS5ReplicaHost"),
				LastUpdateStart: startTime,
				LastUpdateEnd:   endTime,
				Status:          entry.GetAttributeValue("nsds5replicaLastUpdateStatus"),
			}
			// Append to the cache.
			e.replicaSyncInfoCache = append(e.replicaSyncInfoCache, replica)
		}
	}
	// Return cached entries.
	return e.replicaSyncInfoCache, nil
}
