# freeipa-health-metrics

A prometheus/influxdb exporter for FreeIPA metrics to provide indication of cluster health.

Requirements:

- FreeIPA 4 or later
- Golang 1.20 or later
- FreeIPA user with admin privileges

## Install

You can install either by downloading the latest binary release or by building.

### Building

Building should be as simple as running:

```bash
go build
```

### Running as a service

You are likely going to want to run the exporter as a service to ensure it runs at boot and restarts in case of failures. Below is an example service config file you can place in `/etc/systemd/system/freeipa-health-metrics.service` on a linux system to run as a service if you install the binary in `/usr/local/bin/`.

```systemd
[Unit]
Description=FreeIPA Health Metrics
After=network.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
ExecStart=/usr/local/bin/freeipa-health-metrics
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Once the service file is installed, you can run the following to start it:

```bash
systemctl daemon-reload
systemctl start freeipa-health-metrics.service
```

## Config

The default configuration paths are:

- `./config.yaml` - A file in the current working directory.
- `~/.config/freeipa-health-metrics/config.yaml` - A file in your home directory's config path.
- `/etc/ipa/freeipa-health-metrics.yaml` - A file in the IPA config folder.

### For local monitoring

```yaml
---
ldap:
  insecure_skip_verify: true
  connect_method: Secure
  base_dn: dc=example,dc=com
  bind_dn: uid=freeipa-health-metrics,cn=users,cn=accounts,dc=example,dc=com
  bind_password: PASSWORD

freeipa:
  krb5_realm: EXAMPLE.COM
  insecure_skip_verify: true
  username: freeipa-health-metrics
  password: PASSWORD
```

### For remote monitoring

```yaml
---
hostname: ipa1.example.com
ldap:
  insecure_skip_verify: true
  connect_method: Secure
  base_dn: dc=example,dc=com
  bind_dn: uid=freeipa-health-metrics,cn=users,cn=accounts,dc=example,dc=com
  bind_password: PASSWORD

freeipa:
  krb5_realm: EXAMPLE.COM
  insecure_skip_verify: true
  username: freeipa-health-metrics
  password: PASSWORD

  # Disable metrics which only work locally.
  disabled_metrics:
    - krb5_auth
    - krb5_workers
    - proxy_secret
    - group_members
    - ipa_cert_auto_renew
    - ldap_cert_auto_renew
```

### Output to InfluxDB only

```yaml
---
ldap:
  insecure_skip_verify: true
  connect_method: Secure
  base_dn: dc=example,dc=com
  bind_dn: uid=freeipa-health-metrics,cn=users,cn=accounts,dc=example,dc=com
  bind_password: PASSWORD

freeipa:
  krb5_realm: EXAMPLE.COM
  insecure_skip_verify: true
  username: freeipa-health-metrics
  password: PASSWORD

influx_output:
  frequency: 5m
  influx_server: http://example.com:8086
  token: INFLUX_TOKEN
  org: company
  bucket: freeipa

http:
  enabled: false
```
