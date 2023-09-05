package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/jimlambrt/gldap"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Setup global app variable with test config for tests.
func setupLdapTestApp() {
	app = new(App)
	app.flags = new(Flags)
	app.flags.ConfigPath = "test/test_config.yaml"
	app.ReadConfig()
	app.ldapExporter = NewLDAPExporter()
}

// Base LDAP entry, using this as the library doesn't export variables that are useful
// for working the way I wanted with a generic parser.
type ldapEntry struct {
	dn         string
	attributes map[string][]string
}

// Prints the ldap entry with all attributes in ldif format.
// Mainly used in debugging.
func (e *ldapEntry) Print() {
	fmt.Printf("DN: %s\n", e.dn)
	for name, attr := range e.attributes {
		for _, v := range attr {
			fmt.Printf("%s: %s\n", name, v)
		}
	}
}

// Parse ldif file and return all entries.
func ParseLDIF(ldifPath string) (res []*ldapEntry) {
	// Open the file provided.
	ldif, err := os.Open(ldifPath)
	if err != nil {
		log.Fatal("Error opening tests:", err)
	}
	defer ldif.Close()

	// Basic variables used in parsing.
	var dn, fullLine string
	attributes := make(map[string][]string)

	// Parsing handlers.
	scanner := bufio.NewScanner(ldif)
	scanner.Split(bufio.ScanLines)
	parseRx := regexp.MustCompile(`([a-zA-Z0-9:]+):\s(.*)`)

	// Check each line of the file amd parse.
	for scanner.Scan() {
		line := scanner.Text()
		// Ignore comment and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if first chracter is a space.
		isWrapped := false
		for _, c := range line {
			isWrapped = unicode.IsSpace(c)
			break
		}

		// If this is wrapped from the last line, append and read next line.
		if isWrapped {
			// Remove leading spaces from line.
			line = strings.TrimLeftFunc(line, unicode.IsSpace)

			// Add this string to the full line.
			fullLine += line
			continue
		}

		// If the full line has data, parse it.
		if fullLine != "" {
			// Verify we can parse this line.
			if !parseRx.MatchString(fullLine) {
				log.Println("Unable to parse ldif line:", fullLine)
				fullLine = line
				continue
			}

			// Parse line.
			match := parseRx.FindStringSubmatch(fullLine)

			// If is a new entry, append the entry.
			if match[1] == "dn" {
				if dn != "" {
					entry := &ldapEntry{
						dn:         dn,
						attributes: attributes,
					}
					res = append(res, entry)
				}
				// Clear attributes and change the DN to the newly discovered entry.
				attributes = make(map[string][]string)
				dn = match[2]
			} else {
				// This is an attribute, lets add it.
				_, ok := attributes[match[1]]
				if !ok {
					attributes[match[1]] = []string{
						match[2],
					}
				} else {
					attributes[match[1]] = append(attributes[match[1]], match[2])
				}
			}
		}

		// This is a new line, could have additional lines to add with LDIF wrapping.
		fullLine = line
	}

	// If the full line has data, parse it.
	if fullLine != "" {
		// Verify we can parse this line.
		if !parseRx.MatchString(fullLine) {
			log.Println("Unable to parse ldif line:", fullLine)
			return
		}

		// Parse line.
		match := parseRx.FindStringSubmatch(fullLine)

		// If is a new entry, append the entry.
		if match[1] != "dn" {
			// This is an attribute, lets add it.
			_, ok := attributes[match[1]]
			if !ok {
				attributes[match[1]] = []string{
					match[2],
				}
			} else {
				attributes[match[1]] = append(attributes[match[1]], match[2])
			}
		}
	}

	// As this is the end, we need to create the last decoded entry.
	if dn != "" {
		entry := &ldapEntry{
			dn:         dn,
			attributes: attributes,
		}
		res = append(res, entry)
	}

	return
}

const ldapPort = 10389

// LDAP test server.
type LDAPTestServer struct {
	server    *gldap.Server
	responses map[string]string
}

func NewLDAPTestServer() *LDAPTestServer {
	s := new(LDAPTestServer)
	// Requested DN to response ldif file map.
	s.responses = map[string]string{
		"cn=users,cn=accounts,dc=example,dc=com":                         "test/ldap_user_sub.ldif",
		"cn=staged users,cn=accounts,cn=provisioning,dc=example,dc=com":  "test/ldap_stagged_sub.ldif",
		"cn=deleted users,cn=accounts,cn=provisioning,dc=example,dc=com": "test/ldap_deleted_sub.ldif",
		"cn=groups,cn=accounts,dc=example,dc=com":                        "test/ldap_groups.ldif",
		"cn=computers,cn=accounts,dc=example,dc=com":                     "test/ldap_computers.ldif",
		"cn=services,cn=accounts,dc=example,dc=com":                      "test/ldap_services.ldif",
		"cn=ng,cn=alt,dc=example,dc=com":                                 "test/ldap_netgroups.ldif",
		"cn=hostgroups,cn=accounts,dc=example,dc=com":                    "test/ldap_hostgroups.ldif",
		"cn=hbac,dc=example,dc=com":                                      "test/ldap_hbac.ldif",
		"cn=sudorules,cn=sudo,dc=example,dc=com":                         "test/ldap_sudo.ldif",
		"cn=masters,cn=ipa,cn=etc,dc=example,dc=com":                     "test/ldap_masters.ldif",
		"cn=mapping tree,cn=config":                                      "test/ldap_mapping_tree.ldif",
	}
	return s
}

// Simple ldap bind to verify authentication with the ldap metrics work.
func (s *LDAPTestServer) bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	// Setup invalid response which will be sent unless the response code is changed by a successful login.
	resp := r.NewBindResponse(
		gldap.WithResponseCode(gldap.ResultInvalidCredentials),
	)
	// Send response at the end of the function call.
	defer func() {
		w.Write(resp)
	}()

	// Decode bind message from request.
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("not a simple bind message: %s", err)
		return
	}

	// If credentials match config, return success.
	if m.UserName == app.config.LDAP.BindDN && string(m.Password) == app.config.LDAP.BindPassword {
		resp.SetResultCode(gldap.ResultSuccess)
		log.Println("bind success")
		return
	}
}

// Write LDIF entries from file to LDAP request.
func (s *LDAPTestServer) writeLdif(w *gldap.ResponseWriter, r *gldap.Request, ldifPath string) {
	// Parse entries.
	entries := ParseLDIF(ldifPath)
	// For each entry, write it to the request.
	for _, entry := range entries {
		// Print debug info.
		// entry.Print()

		// Make a response entry for this request and write it.
		w.Write(r.NewSearchResponseEntry(entry.dn, gldap.WithAttributes(entry.attributes)))
	}
}

// Handle LDAP search requests.
func (s *LDAPTestServer) searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	// Setup general response.
	resp := r.NewSearchDoneResponse()
	defer func() {
		w.Write(resp)
	}()

	// Get message from request.
	m, err := r.GetSearchMessage()
	if err != nil {
		log.Printf("not a search message: %s", err)
		return
	}

	// Print debug info.
	// log.Printf("search base dn: %s", m.BaseDN)
	// log.Printf("search scope: %d", m.Scope)
	// log.Printf("search filter: %s", m.Filter)
	// log.Printf("search attributes: %v", m.Attributes)

	// Send test ldif response based on request DN.
	ldifFile, ok := s.responses[m.BaseDN]
	if ok {
		s.writeLdif(w, r, ldifFile)
		resp.SetResultCode(gldap.ResultSuccess)
	}
}

// Helper to start and wait for server to be running.
func (s *LDAPTestServer) Run() {
	go s.Start()
	for s.server == nil || !s.server.Ready() {
	}
}

// Helper to stop LDAP server.
func (s *LDAPTestServer) Stop() {
	if s.server != nil {
		s.server.Stop()
	}
}

// Setup LDAP test server for verifying metrics.
func (s *LDAPTestServer) Start() {
	server, err := gldap.NewServer()
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}
	// Set global variable for test function access.
	s.server = server

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(s.bindHandler)
	r.Search(s.searchHandler)
	server.Router(r)

	// Run the LDAP test server.
	server.Run(fmt.Sprintf("127.0.0.1:%d", ldapPort))
}

// Main LDAP test function that verifies metrics for LDAP works.
func TestLdap(t *testing.T) {
	// Setup configs.
	setupLdapTestApp()
	// Run the LDAP test server.
	server := NewLDAPTestServer()
	server.Run()

	// Open the expected prometheus metrics.
	expected, err := os.Open("test/ldap.metrics")
	if err != nil {
		t.Fatal("Error opening tests:", err)
	}
	defer expected.Close()

	// Test the LDAP exporter and verify metrics match what's expected.
	err = testutil.CollectAndCompare(app.ldapExporter, expected)
	// If results are not as expected, fail test with the error.
	if err != nil {
		t.Fatal("Unexpected metrics returned:", err)
	}

	// Remove all responses from ldap server to cause failure in all metrics.
	server.responses = nil

	// Open the expected prometheus metrics.
	expected, err = os.Open("test/ldap_fail.metrics")
	if err != nil {
		t.Fatal("Error opening tests:", err)
	}
	defer expected.Close()

	// Test the LDAP exporter and verify metrics match what's expected.
	err = testutil.CollectAndCompare(app.ldapExporter, expected)
	// If results are not as expected, fail test with the error.
	if err != nil {
		t.Fatal("Unexpected metrics returned:", err)
	}

	// Test failure to connect.
	app.config.LDAP.Address = "bad-address"

	// Open the expected prometheus metrics.
	expected, err = os.Open("test/ldap_fail_connect.metrics")
	if err != nil {
		t.Fatal("Error opening tests:", err)
	}
	defer expected.Close()

	// Test the LDAP exporter and verify metrics match what's expected.
	err = testutil.CollectAndCompare(app.ldapExporter, expected)
	// If results are not as expected, fail test with the error.
	if err != nil {
		t.Fatal("Unexpected metrics returned:", err)
	}

	// We're done, let's stop serving the test LDAP server.
	server.Stop()
}
