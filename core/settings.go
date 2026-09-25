package core

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
)

// Setting describes a configuration setting.
// CLI, config import/export and the TUI configurator are built from Settings.
type Setting struct {
	// Key is the setting name, environment variable is COCOSMAIL_<KEY>
	Key     string
	Section string
	// Default value, "" means no value
	Default  string
	Required bool
	// RequiredWith is a bool setting: when it's true, this setting is required
	RequiredWith string
	Description  string
	// Restart means a running server applies the new value after a restart only
	Restart bool
	// Secret values are not shown unless asked
	Secret bool
	// Bootstrap settings tell where the database is, so they're never stored in it
	Bootstrap bool
	// Choices are the allowed values, if limited
	Choices []string
	// Validate checks a value, in addition to the type and choices check
	Validate func(value string) error
}

// Settings are all cocosmail settings
var Settings = []Setting{
	// general
	{Key: "me", Section: "general", Required: true,
		Description: "Hostname of this server, used in HELO/EHLO and as default for outgoing mail"},
	{Key: "hide_server_signature", Section: "general", Default: "false",
		Description: "Hide cocosmail version in SMTP greeting"},
	{Key: "debug_enabled", Section: "general", Default: "false", Restart: true,
		Description: "Log debug messages"},
	{Key: "logpath", Section: "general", Default: "stdout", Restart: true,
		Description: `Where to log: "stdout", "discard" or a file name, the file is log/NAME next to the binary`},
	{Key: "tempdir", Section: "general", Default: "/tmp",
		Description: "Temporary directory for scanning and filtering, a RAM disk like /dev/shm is recommended"},
	{Key: "plugin_path", Section: "general", Default: "plugins",
		Description: "Directory of plugins"},

	// database
	{Key: "db_driver", Section: "database", Default: "sqlite3", Bootstrap: true, Restart: true,
		Description: "Database driver: sqlite3, mysql or postgres",
		Choices:     []string{"sqlite3", "mysql", "postgres"}},
	{Key: "db_source", Section: "database", Default: defaultSqliteSource, Bootstrap: true, Restart: true, Secret: true,
		Description: "Database source. For sqlite3 the file, relative to the cocosmail binary directory. " +
			"MySQL: user:passwd@tcp(ip:port)/cocosmail?parseTime=true, " +
			"PostgreSQL: user=cocosmail dbname=cocosmail sslmode=disable"},

	// store
	{Key: "store_driver", Section: "store", Default: "disk", Restart: true,
		Description: "Where messages waiting in queue are stored: disk",
		Choices:     []string{"disk"}},
	{Key: "store_source", Section: "store", Default: "store", Restart: true,
		Description: "Directory of the disk store"},

	// cluster
	{Key: "cluster_mode_enabled", Section: "cluster", Default: "false", Restart: true,
		Description: "Run cocosmail as a cluster"},
	{Key: "nsq_lookupd_tcp_addresses", Section: "cluster", Restart: true,
		Description: "nsqlookupd TCP addresses in cluster mode, IP:PORT separated by ;"},
	{Key: "nsq_lookupd_http_addresses", Section: "cluster", Restart: true,
		Description: "nsqlookupd HTTP addresses in cluster mode, IP:PORT separated by ;"},

	// smtpd
	{Key: "smtpd_launch", Section: "smtpd", Default: "false", Restart: true,
		Description: "Launch the SMTP server"},
	{Key: "smtpd_dsns", Section: "smtpd", RequiredWith: "smtpd_launch", Restart: true,
		Description: "SMTP listeners separated by ;, each IP:PORT:HOSTNAME:ssl|nossl:CERT. " +
			"IPv6 in brackets: [2001:db8::1]. [::] or 0.0.0.0 listen on all IPv4 and IPv6 addresses. " +
			"ssl: TLS from the start (465), nossl: STARTTLS available (25, 587). " +
			"Certificate: ssl/smtp-CERT.crt and .key",
		Validate: validateDsns},
	{Key: "smtpd_server_timeout", Section: "smtpd", Default: "300",
		Description: "Seconds before an idle SMTP client is disconnected (RFC 5321 4.5.3.2.7: 300)"},
	{Key: "smtpd_max_databytes", Section: "smtpd", Default: "0",
		Description: "Maximum size of an incoming message in bytes, 0 is unlimited"},
	{Key: "smtpd_max_hops", Section: "smtpd", Default: "10",
		Description: "Maximum Received headers, to prevent loops"},
	{Key: "smtpd_max_rcpt", Section: "smtpd", Default: "0",
		Description: "Maximum RCPT TO per message, 0 is unlimited (RFC compliant)"},
	{Key: "smtpd_max_bad_rcpt", Section: "smtpd", Default: "0",
		Description: "Drop the session after this many unknown recipients, 0 never drops (RFC compliant)"},
	{Key: "smtpd_max_vrfy", Section: "smtpd", Default: "0",
		Description: "Maximum VRFY commands per session, 0 is unlimited"},
	{Key: "smtpd_concurrency_incoming", Section: "smtpd", Default: "20",
		Description: "Maximum simultaneous incoming SMTP sessions"},
	{Key: "smtpd_hide_received_from_auth", Section: "smtpd", Default: "true",
		Description: "Hide IP and hostname in Received header for authenticated senders"},
	{Key: "smtpd_spf_check", Section: "smtpd", Default: "true",
		Description: "Check SPF of incoming mail and add a Received-SPF header"},
	{Key: "smtpd_spf_action", Section: "smtpd", Default: "accept:accept:accept:accept:accept:accept",
		Description: "accept or reject for each SPF result, in order: none:neutral:pass:fail:softfail:permerror",
		Validate:    validateSpfAction},
	{Key: "smtpd_scan_clamav_enabled", Section: "smtpd", Default: "false",
		Description: "Scan incoming mail with ClamAV"},
	{Key: "smtpd_scan_clamav_dsns", Section: "smtpd", Default: "/var/run/clamav/clamd.ctl",
		Description: "clamd socket, or name:ip:port"},

	// deliverd
	{Key: "deliverd_launch", Section: "deliverd", Default: "false", Restart: true,
		Description: "Launch delivery of queued mail"},
	{Key: "deliverd_local_ips", Section: "deliverd", Default: "0.0.0.0&::",
		Description: "Local IPs for outgoing mail, & for failover or | for round robin (don't mix). " +
			"0.0.0.0 is any IPv4, :: any IPv6. Add :hostname for HELO, IPv6 in brackets: [2001:db8::1]:mail.example.com",
		Validate: validateLocalIps},
	{Key: "deliverd_concurrency_local", Section: "deliverd", Default: "50", Restart: true,
		Description: "Maximum simultaneous local deliveries"},
	{Key: "deliverd_concurrency_remote", Section: "deliverd", Default: "50", Restart: true,
		Description: "Maximum simultaneous remote deliveries"},
	{Key: "deliverd_queue_lifetime", Section: "deliverd", Default: "10080",
		Description: "Minutes a message stays in queue before it bounces"},
	{Key: "deliverd_queue_bounces_lifetime", Section: "deliverd", Default: "10080",
		Description: "Minutes a bounce stays in queue before it's discarded"},
	{Key: "deliverd_remote_timeout", Section: "deliverd", Default: "300",
		Description: "Seconds to wait for a remote server reply"},
	{Key: "deliverd_remote_tls_skipverify", Section: "deliverd", Default: "false",
		Description: "Accept any certificate from remote servers, many have self-signed ones"},
	{Key: "deliverd_remote_tls_fallback", Section: "deliverd", Default: "false",
		Description: "Send in clear text if STARTTLS fails"},
	{Key: "deliverd_remote_use_same_host", Section: "deliverd", Default: "true",
		Description: "Send from the host that received the message, as configured in deliverd_local_ips or me"},
	{Key: "deliverd_dkim_sign", Section: "deliverd", Default: "false",
		Description: "DKIM sign outgoing mail"},

	// rfc
	{Key: "rfc_helo_mandatory", Section: "rfc", Default: "false",
		Description: "Require HELO/EHLO before other commands (RFC 5321 4.1.1.1)"},
	{Key: "rfc_helo_need_fqn", Section: "rfc", Default: "false",
		Description: "Require a resolvable hostname or an address in HELO (RFC 5321 2.3.5), many clients don't send one"},
	{Key: "rfc_mailfrom_localpart_size", Section: "rfc", Default: "false",
		Description: "Reject MAIL FROM local part longer than 64 characters (RFC 5321 4.5.3.1.1)"},

	// users
	{Key: "users_home_base", Section: "users", Default: "mailboxes",
		Description: "Directory of mailboxes"},
	{Key: "users_mailbox_default_quota", Section: "users",
		Description: "Default mailbox quota, e.g. 1G, 100M, 100K"},
	{Key: "lda_type", Section: "users", Default: "maildir", Restart: true,
		Description: "Local delivery: maildir (built in) or dovecot (Dovecot LDA)",
		Choices:     []string{"maildir", "dovecot"}},
	{Key: "dovecot_lda", Section: "users", Default: "/usr/lib/dovecot/dovecot-lda",
		Description: "Path of dovecot-lda when lda_type is dovecot"},

	// pop3d
	{Key: "pop3d_launch", Section: "pop3d", Default: "false", Restart: true,
		Description: "Launch the POP3 server"},
	{Key: "pop3d_dsns", Section: "pop3d", RequiredWith: "pop3d_launch", Restart: true,
		Description: "POP3 listeners, same format as smtpd_dsns. Must be ssl, nossl only on loopback. " +
			"Certificate: ssl/pop3-CERT.crt and .key",
		Validate: validateDsns},
	{Key: "pop3d_server_timeout", Section: "pop3d", Default: "300", Restart: true,
		Description: "Seconds before an idle POP3 client is disconnected"},

	// rest
	{Key: "rest_server_launch", Section: "rest", Default: "false", Restart: true,
		Description: "Launch the REST API server"},
	{Key: "rest_server_ip", Section: "rest", Default: "127.0.0.1", Restart: true,
		Description: "REST server IP, IPv6 without brackets",
		Validate:    validateIP},
	{Key: "rest_server_port", Section: "rest", Default: "8080", Restart: true,
		Description: "REST server port",
		Validate:    validatePort},
	{Key: "rest_server_is_tls", Section: "rest", Default: "false", Restart: true,
		Description: "Use HTTPS, certificate ssl/web_server.crt and .key"},
	{Key: "rest_server_login", Section: "rest",
		Description: "REST HTTP auth login"},
	{Key: "rest_server_passwd", Section: "rest", Secret: true,
		Description: "REST HTTP auth password"},
}

// removedSettings were settings of older versions, for features that were
// never used: microservices (URLs called by smtpd and deliverd) and OpenStack
// object storage. They're ignored, and deleted from the database.
var removedSettings = map[string]bool{
	"ms_smtpd_newclient":         true,
	"ms_smtpd_helo":              true,
	"ms_smtpd_mail_from":         true,
	"ms_smtpd_rcptto":            true,
	"ms_smtpd_data":              true,
	"ms_smtpd_before_queueing":   true,
	"ms_smtpd_send_telemetry":    true,
	"ms_deliverd_get_routes":     true,
	"ms_deliverd_send_telemetry": true,
	"openstack_enable":           true,
}

var settingsByKey = func() map[string]*Setting {
	m := make(map[string]*Setting, len(Settings))
	for i := range Settings {
		m[Settings[i].Key] = &Settings[i]
	}
	return m
}()

// SettingByKey returns the setting with key
func SettingByKey(key string) (*Setting, bool) {
	s, ok := settingsByKey[key]
	return s, ok
}

// MissingSettings returns the required settings without value in values,
// as environment variable names
func MissingSettings(values map[string]string) (missing []string) {
	for _, s := range Settings {
		if values[s.Key] != "" {
			continue
		}
		if s.Required || (s.RequiredWith != "" && values[s.RequiredWith] == "true") {
			missing = append(missing, SettingEnvName(s.Key))
		}
	}
	return
}

// SettingEnvName returns the environment variable name of a setting
func SettingEnvName(key string) string {
	return "COCOSMAIL_" + strings.ToUpper(key)
}

// SettingsDefaults returns the default value of all settings
func SettingsDefaults() map[string]string {
	values := make(map[string]string, len(Settings))
	for _, s := range Settings {
		values[s.Key] = s.Default
	}
	return values
}

// ValidateSetting checks that value is valid for setting key
func ValidateSetting(key, value string) error {
	s, ok := SettingByKey(key)
	if !ok {
		return errors.New("unknown setting " + SettingEnvName(key))
	}
	var cfg configValues
	field := reflect.ValueOf(&cfg).Elem().Field(configFields[key])
	// empty string is "no value"
	if value == "" && field.Kind() == reflect.String {
		return nil
	}
	if err := setConfigField(field, value); err != nil {
		return errors.New(SettingEnvName(key) + ": " + err.Error())
	}
	if len(s.Choices) > 0 {
		if err := oneOf(s.Choices...)(value); err != nil {
			return errors.New(SettingEnvName(key) + ": " + err.Error())
		}
	}
	if s.Validate != nil {
		if err := s.Validate(value); err != nil {
			return errors.New(SettingEnvName(key) + ": " + err.Error())
		}
	}
	return nil
}

func oneOf(allowed ...string) func(string) error {
	return func(v string) error {
		for _, a := range allowed {
			if v == a {
				return nil
			}
		}
		return fmt.Errorf("%q must be one of: %s", v, strings.Join(allowed, ", "))
	}
}

func validateDsns(v string) error {
	_, err := GetDsnsFromString(v)
	return err
}

func validateLocalIps(v string) error {
	if strings.Contains(v, "&") && strings.Contains(v, "|") {
		return errors.New("don't mix & and |")
	}
	for _, ip := range strings.FieldsFunc(v, func(r rune) bool { return r == '&' || r == '|' }) {
		if _, _, err := ParseIPAndName(ip); err != nil {
			return err
		}
	}
	return nil
}

func validateSpfAction(v string) error {
	actions := strings.Split(v, ":")
	if len(actions) != 6 {
		return errors.New("needs 6 actions separated by :, for none:neutral:pass:fail:softfail:permerror")
	}
	for _, a := range actions {
		if a != "accept" && a != "reject" {
			return fmt.Errorf("%q must be accept or reject", a)
		}
	}
	return nil
}

func validateIP(v string) error {
	if net.ParseIP(v) == nil {
		return fmt.Errorf("%q is not an IP address", v)
	}
	return nil
}

func validatePort(v string) error {
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%q is not a port (1-65535)", v)
	}
	return nil
}

// SettingKind returns the type of a setting: reflect.String, Int, Uint64 or Bool
func SettingKind(key string) reflect.Kind {
	i, ok := configFields[key]
	if !ok {
		return reflect.Invalid
	}
	return reflect.TypeOf(configValues{}).Field(i).Type.Kind()
}
