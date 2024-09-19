package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkyr/fig"
)

// Main configuration structure.
type Config struct {
	// Used as the FreeIPA server hostname in multiple checks.
	// If no address configurations for metric exporters are defined,
	// the hostname will be used to set defaults.
	Hostname string `fig:"hostname"`

	// Metric exporters configurations.
	LDAP    LDAPConfig    `fig:"ldap"`
	FreeIPA FreeIPAConfig `fig:"freeipa"`

	// Metric outputs configurations.
	HTTP   HTTPOutputConfig   `fig:"http_output"`
	Influx InfluxOutputConfig `fig:"influx_output"`

	// File path configurations for binaries and config files.
	Krb5SysConfigPath  string `fig:"krb5_sysconfig_path"`
	Krb5KeytabPath     string `fig:"krb5_keytab_path"`
	Krb5ConfigPath     string `fig:"krb5_config_path"`
	PKITomcatServerXML string `fig:"pki_tomcat_server_xml"`
	HTTPDPKIProxyConf  string `fig:"httpd_pki_proxy_conf"`
	KInitBin           string `fig:"kinit_bin"`
	KListBin           string `fig:"klist_bin"`
	GetCertBIN         string `fig:"getcert_bin"`
}

const (
	// Use standard LDAP connection.
	LDAPMethodUnsecure = "Unsecure"
	// Use LDAP over TLS.
	LDAPMethodSecure = "Secure"
	// Use StartTLS over standard LDAP connection.
	LDAPMethodStartTLS = "StartTLS"
)

// Configurations relating to LDAP.
type LDAPConfig struct {
	Address            string `fig:"address"`
	CACertificate      string `fig:"ca_certificate"`
	InsecureSkipVerify bool   `fig:"insecure_skip_verify"`
	ConnectMethod      string `fig:"connect_method"`
	BaseDN             string `fig:"base_dn"`
	BindDN             string `fig:"bind_dn"`
	BindPassword       string `fig:"bind_password"`
	SearchSizeLimit    int    `fig:"search_size_limit"`

	DisabledMetrics []string `fig:"disabled_metrics"`
}

// UNIX system group members for the FreeIPA configuration check of file system state.
type GroupMembers struct {
	Name    string   `fig:"name"`
	Members []string `fig:"members"`
}

// Configurations relating to FreeIPA API and configuration testing.
type FreeIPAConfig struct {
	// Kerberos config can be used for both API authentication and for kinit test.
	// To use for API authentication, simply do not supply an username/password.
	// It is recommended to have it configured for the kinit test to function.
	Krb5Realm     string `fig:"krb5_realm"`
	Krb5Principal string `fig:"krb5_principal"`

	Host               string `fig:"host"`
	CACertificate      string `fig:"ca_certificate"`
	InsecureSkipVerify bool   `fig:"insecure_skip_verify"`
	Username           string `fig:"username"`
	Password           string `fig:"password"`

	GroupMembers []GroupMembers `fig:"group_mebers"`

	DisabledMetrics []string `fig:"disabled_metrics"`
}

// Configurations relating to HTTP server.
type HTTPOutputConfig struct {
	Enabled     bool   `fig:"enabled"`
	BindAddr    string `fig:"bind_addr"`
	Port        uint   `fig:"port"`
	MetricsPath string `fig:"metrics_path"`
}

// If you want to output to InfluxDB either via Kafka or to InfluxDB API directly,
// these configurations allow you to set output to occur at a specified frequency.
type InfluxOutputConfig struct {
	Frequency time.Duration `fig:"frequency"`

	KafkaBrokers            []string `fig:"kafka_brokers"`
	KafkaTopic              string   `fig:"kafka_topic"`
	KafkaUsername           string   `fig:"kafka_usernamne"`
	KafkaPassword           string   `fig:"kafka_password"`
	KafkaInsecureSkipVerify bool     `fig:"kafka_insecure_skip_verify"`
	KafkaOutputFormat       string   `fig:"kafka_output_format"` // Either lineprotocol or json. Default: lineprotocol

	InfluxServer string `fig:"influx_server"`
	Token        string `fig:"token"`
	Org          string `fig:"org"`
	Bucket       string `fig:"bucket"`
}

// Read the configuration file.
func (a *App) ReadConfig() {
	// Gets the current user for getting the home directory.
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Configuration paths.
	localConfig, _ := filepath.Abs("./config.yaml")
	homeDirConfig := usr.HomeDir + "/.config/freeipa-health-metrics/config.yaml"
	etcConfig := "/etc/ipa/freeipa-health-metrics.yaml"

	// Determine which configuration to use.
	var configFile string
	if _, err := os.Stat(app.flags.ConfigPath); err == nil && app.flags.ConfigPath != "" {
		configFile = app.flags.ConfigPath
	} else if _, err := os.Stat(localConfig); err == nil {
		configFile = localConfig
	} else if _, err := os.Stat(homeDirConfig); err == nil {
		configFile = homeDirConfig
	} else if _, err := os.Stat(etcConfig); err == nil {
		configFile = etcConfig
	} else {
		log.Fatal("Unable to find a configuration file.")
	}

	// Set defaults.
	config := &Config{
		HTTP: HTTPOutputConfig{
			Enabled:     true,
			Port:        9101,
			MetricsPath: "/metrics",
		},
		LDAP: LDAPConfig{
			SearchSizeLimit: 100,
		},
		FreeIPA: FreeIPAConfig{
			GroupMembers: []GroupMembers{
				{
					Name:    "ipaapi",
					Members: []string{"apache"},
				},
			},
		},

		Krb5SysConfigPath:  "/etc/sysconfig/krb5kdc",
		Krb5KeytabPath:     "/etc/krb5.keytab",
		Krb5ConfigPath:     "/etc/krb5.conf",
		PKITomcatServerXML: "/etc/pki/pki-tomcat/server.xml",
		HTTPDPKIProxyConf:  "/etc/httpd/conf.d/ipa-pki-proxy.conf",
		KInitBin:           "/usr/bin/kinit",
		KListBin:           "/usr/bin/klist",
		GetCertBIN:         "/usr/bin/getcert",
	}

	// Load configuration.
	filePath, fileName := path.Split(configFile)
	err = fig.Load(config,
		fig.File(fileName),
		fig.Dirs(filePath),
	)
	if err != nil {
		log.Printf("Error parsing configuration: %s\n", err)
		return
	}

	// If no hostname is defined in config, pull system hostname.
	if config.Hostname == "" {
		cmd := exec.Command("/bin/hostname", "-f")
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			log.Println("Error getting hostname:", err)
			return
		}
		config.Hostname = strings.TrimRight(out.String(), "\n")
	}

	// Use configured hostname as defaults for host related configs.
	if config.FreeIPA.Krb5Principal == "" {
		config.FreeIPA.Krb5Principal = "host/" + config.Hostname
	}
	if config.LDAP.Address == "" {
		config.LDAP.Address = "ldaps://" + config.Hostname + ":636"
	}
	if config.FreeIPA.Host == "" {
		config.FreeIPA.Host = config.Hostname
	}

	// Flag Overrides.
	if app.flags.HTTPBind != "" {
		config.HTTP.BindAddr = app.flags.HTTPBind
	}
	if app.flags.HTTPPort != 0 {
		config.HTTP.Port = app.flags.HTTPPort
	}
	if app.flags.HTTPMetricsPath != "" {
		config.HTTP.MetricsPath = app.flags.HTTPMetricsPath
	}

	// Verify at least one output is enabled.
	if !config.HTTP.Enabled && (len(app.config.Influx.KafkaBrokers) == 0 || app.config.Influx.KafkaTopic == "") && (config.Influx.InfluxServer == "" && config.Influx.Token == "" && config.Influx.Org == "" && config.Influx.Bucket == "") {
		log.Println("No output services are configured.")
		return
	}

	// Set global config structure.
	app.config = config
}
