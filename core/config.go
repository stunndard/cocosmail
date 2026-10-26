package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

var c Config

// Config holds cocosmail settings.
// Which settings exist, their defaults and descriptions are in Settings,
// values come from defaults, environment and the settings table (see Bootstrap).
type Config struct {
	sync.Mutex
	cfg configValues
	// raw values by setting key, as loaded
	values map[string]string
}

// configValues are the parsed settings, field tag "name" is the setting key
type configValues struct {
	ClusterModeEnabled  bool   `name:"cluster_mode_enabled"`
	Me                  string `name:"me"`
	PluginPath          string `name:"plugin_path"`
	TempDir             string `name:"tempdir"`
	LogPath             string `name:"logpath"`
	LogMaxSize          int    `name:"log_max_size"`
	LogMaxFiles         int    `name:"log_max_files"`
	DebugEnabled        bool   `name:"debug_enabled"`
	HideServerSignature bool   `name:"hide_server_signature"`

	DbDriver string `name:"db_driver"`
	DbSource string `name:"db_source"`

	// mail spool driver and location
	StoreDriver string `name:"store_driver"`
	StoreSource string `name:"store_source"`

	//NsqdEnbleLogging        bool   `name:"nsqd_eanble_logging"`
	NSQLookupdTcpAddresses  string `name:"nsq_lookupd_tcp_addresses"`
	NSQLookupdHttpAddresses string `name:"nsq_lookupd_http_addresses"`

	LaunchSmtpd               bool   `name:"smtpd_launch"`
	SmtpdDsns                 string `name:"smtpd_dsns"`
	SmtpdServerTimeout        int    `name:"smtpd_server_timeout"`
	SmtpdMaxDataBytes         uint64 `name:"smtpd_max_databytes"`
	SmtpdMaxHops              int    `name:"smtpd_max_hops"`
	SmtpdMaxRcptTo            int    `name:"smtpd_max_rcpt"`
	SmtpdMaxBadRcptTo         int    `name:"smtpd_max_bad_rcpt"`
	SmtpdMaxVrfy              int    `name:"smtpd_max_vrfy"`
	SmtpdClamavEnabled        bool   `name:"smtpd_scan_clamav_enabled"`
	SmtpdClamavDsns           string `name:"smtpd_scan_clamav_dsns"`
	SmtpdConcurrencyIncoming  int    `name:"smtpd_concurrency_incoming"`
	SmtpdHideReceivedFromAuth bool   `name:"smtpd_hide_received_from_auth"`
	SmtpdSPFCheck             bool   `name:"smtpd_spf_check"`
	SmtpdSPFAction            string `name:"smtpd_spf_action"`

	LaunchDeliverd               bool   `name:"deliverd_launch"`
	LocalIps                     string `name:"deliverd_local_ips"`
	DeliverdConcurrencyLocal     int    `name:"deliverd_concurrency_local"`
	DeliverdConcurrencyRemote    int    `name:"deliverd_concurrency_remote"`
	DeliverdQueueLifetime        int    `name:"deliverd_queue_lifetime"`
	DeliverdQueueBouncesLifetime int    `name:"deliverd_queue_bounces_lifetime"`
	DeliverdRemoteTimeout        int    `name:"deliverd_remote_timeout"`
	DeliverdRemoteTLSSkipVerify  bool   `name:"deliverd_remote_tls_skipverify"`
	DeliverdRemoteTLSFallback    bool   `name:"deliverd_remote_tls_fallback"`
	DeliverdRemoteUseSameHost    bool   `name:"deliverd_remote_use_same_host"`
	DeliverdDkimSign             bool   `name:"deliverd_dkim_sign"`

	// RFC compliance
	// RFC 5321 2.3.5: the domain name givent MUST be either a primary hostname
	// (resovable) or an address
	RFCHeloNeedsFqnOrAddress bool `name:"rfc_helo_need_fqn"`
	// RFC 5321 4.1.1.1 a client SHOULD start an SMTP session with the EHLO
	// command
	RFCHeloMandatory bool `name:"rfc_helo_mandatory"`

	RFCMailFromLocalpartSize bool `name:"rfc_mailfrom_localpart_size"`

	LaunchRestServer bool   `name:"rest_server_launch"`
	RestServerIp     string `name:"rest_server_ip"`
	RestServerPort   int    `name:"rest_server_port"`
	RestServerIsTls  bool   `name:"rest_server_is_tls"`
	RestServerLogin  string `name:"rest_server_login"`
	RestServerPasswd string `name:"rest_server_passwd"`

	UsersHomeBase           string `name:"users_home_base"`
	UserMailboxDefaultQuota string `name:"users_mailbox_default_quota"`

	DovecotLda string `name:"dovecot_lda"`
	LdaType    string `name:"lda_type"`

	LaunchImap bool   `name:"imapd_launch"`
	ImapdDsns  string `name:"imapd_dsns"`

	LaunchPop3         bool   `name:"pop3d_launch"`
	Pop3dDsns          string `name:"pop3d_dsns"`
	Pop3dServerTimeout int    `name:"pop3d_server_timeout"`
}

// configFields maps setting key to configValues field index
var configFields = func() map[string]int {
	m := make(map[string]int)
	t := reflect.TypeOf(configValues{})
	for i := 0; i < t.NumField(); i++ {
		m[t.Field(i).Tag.Get("name")] = i
	}
	return m
}()

// InitConfig initialise config from defaults, config file (file mode) and environment
func InitConfig(prefix string) (*Config, error) {
	values, _, _, err := ExternalSettings()
	if err != nil {
		return nil, err
	}
	if err := c.Load(values); err != nil {
		return nil, err
	}
	c.stayUpToDate()
	return &c, nil
}

// stayUpToDate keeps config up to date
// by quering etcd (if enabled) or by reloading env var
func (c *Config) stayUpToDate() {
	go func() {
		for {
			// do something
			time.Sleep(1 * time.Second)
		}
	}()
}

// Load sets config from setting defaults, overridden by values (setting key -> raw value)
func (c *Config) Load(values map[string]string) error {
	merged := SettingsDefaults()
	for k, v := range values {
		merged[k] = v
	}
	var cfg configValues
	elem := reflect.ValueOf(&cfg).Elem()
	for key, raw := range merged {
		if err := ValidateSetting(key, raw); err != nil {
			return err
		}
		if err := setConfigField(elem.Field(configFields[key]), raw); err != nil {
			return errors.New(SettingEnvName(key) + ": " + err.Error())
		}
	}
	c.Lock()
	defer c.Unlock()
	c.cfg = cfg
	c.values = merged
	return nil
}

// CheckRequired returns an error if required settings have no value
func (c *Config) CheckRequired() error {
	if missing := c.MissingSettings(); len(missing) > 0 {
		return errors.New("missing settings: " + strings.Join(missing, ", "))
	}
	return nil
}

// MissingSettings returns the required settings without value
func (c *Config) MissingSettings() []string {
	c.Lock()
	defer c.Unlock()
	return MissingSettings(c.values)
}

// Values returns a copy of the raw values by setting key
func (c *Config) Values() map[string]string {
	c.Lock()
	defer c.Unlock()
	values := make(map[string]string, len(c.values))
	for k, v := range c.values {
		values[k] = v
	}
	return values
}

// setConfigField parses raw into field according to its type
func setConfigField(field reflect.Value, raw string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(raw, 0, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("%q is not a valid number", raw)
		}
		field.SetInt(v)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(raw, 0, field.Type().Bits())
		if err != nil {
			return fmt.Errorf("%q is not a valid positive number", raw)
		}
		field.SetUint(v)
	case reflect.Bool:
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("%q is not true or false", raw)
		}
		field.SetBool(v)
	default:
		return errors.New("unsupported type " + field.Type().String())
	}
	return nil
}

// SettingsFromEnv returns settings set in environment, as PREFIX_KEY.
// Empty variables are ignored.
func SettingsFromEnv(prefix string) map[string]string {
	values := make(map[string]string)
	for _, s := range Settings {
		if v := os.Getenv(strings.ToUpper(prefix + "_" + s.Key)); v != "" {
			values[s.Key] = v
		}
	}
	return values
}

// Getters
// There must be other - shorter - way sto do this (via reflect)
// but if there is duplicate code, i think it's the more effcient way (light)

// GetClusterModeEnabled return clusterModeEnabled
func (c *Config) GetClusterModeEnabled() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.ClusterModeEnabled
}

// GetMe return me
func (c *Config) GetMe() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.Me
}

// GetBasePath return base directory: where the binary is, see BaseDir
func (c *Config) GetBasePath() string {
	return BaseDir()
}

// GetPluginPath return plugin directory
func (c *Config) GetPluginPath() string {
	c.Lock()
	defer c.Unlock()
	return AbsPath(c.cfg.PluginPath)
}

// GetDebugEnabled returns debugEnabled
func (c *Config) GetDebugEnabled() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DebugEnabled
}

// GetHideServerSignature HideServerSignature
func (c *Config) GetHideServerSignature() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.HideServerSignature
}

// GetTempDir return temp directory
func (c *Config) GetTempDir() string {
	c.Lock()
	defer c.Unlock()
	return AbsPath(c.cfg.TempDir)
}

// LogDir is the directory of the log file, next to the binary
const LogDir = "log"

// GetLogPath returns where to log: "stdout", "discard" or the log file,
// log/NAME next to the binary. Only the last part of a path is used: before,
// the setting was a directory.
func (c *Config) GetLogPath() string {
	c.Lock()
	defer c.Unlock()
	switch c.cfg.LogPath {
	case "", "stdout":
		return "stdout"
	case "discard":
		return "discard"
	}
	return filepath.Join(BaseDir(), LogDir, filepath.Base(c.cfg.LogPath))
}

// GetLogMaxSize returns the size in MB at which the log file is rotated, 0: never
func (c *Config) GetLogMaxSize() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LogMaxSize
}

// GetLogMaxFiles returns how many rotated log files are kept
func (c *Config) GetLogMaxFiles() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LogMaxFiles
}

// GetDbDriver returns database driver
func (c *Config) GetDbDriver() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DbDriver
}

// GetDbSource return database source
// sqlite file is relative to BaseDir, default is db/cocosmail.db
func (c *Config) GetDbSource() string {
	c.Lock()
	defer c.Unlock()
	return dbSource(c.cfg.DbDriver, c.cfg.DbSource)
}

// defaultSqliteSource is the database in db/ next to the binary
const defaultSqliteSource = "db/cocosmail.db?_busy_timeout=60000"

// dbSource returns the database source to open
func dbSource(driver, source string) string {
	if driver != "sqlite3" {
		return source
	}
	if source == "" {
		source = defaultSqliteSource
	}
	return sqliteAbsSource(source)
}

// GetStoreDriver return source driver
// disk
// runabove
func (c *Config) GetStoreDriver() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.StoreDriver
}

// GetStoreSource return store source
func (c *Config) GetStoreSource() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.StoreSource
}

// GetLaunchSmtpd returns true if smtpd have to be launched
func (c *Config) GetLaunchSmtpd() bool {
	c.Lock()
	r := c.cfg.LaunchSmtpd
	c.Unlock()
	return r
}

// GetSmtpdDsns returns smtpd dsns
func (c *Config) GetSmtpdDsns() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdDsns
}

// GetSmtpdServerTimeout return smtpdTransactionTimeout
func (c *Config) GetSmtpdServerTimeout() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdServerTimeout
}

// GetSmtpdMaxDataBytes returns max size of accepted email
func (c *Config) GetSmtpdMaxDataBytes() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdMaxDataBytes
}

// GetSmtpdMaxHops returns the number of relay a mail can traverser
func (c *Config) GetSmtpdMaxHops() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdMaxHops
}

// GetSmtpdMaxRcptTo returns the maximum number of RCPT TO commands
func (c *Config) GetSmtpdMaxRcptTo() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdMaxRcptTo
}

// GetSmtpdMaxBadRcptTo returns the maximum number of bad RCPT TO commands
func (c *Config) GetSmtpdMaxBadRcptTo() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdMaxBadRcptTo
}

// GetSmtpdMaxVrfy return GetSmtpdMaxVrfy
func (c *Config) GetSmtpdMaxVrfy() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdMaxVrfy
}

// GetSmtpdClamavEnabled returns if clamav scan is enable
func (c *Config) GetSmtpdClamavEnabled() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdClamavEnabled
}

// GetSmtpdClamavDsns returns clamav dsns
func (c *Config) GetSmtpdClamavDsns() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdClamavDsns
}

// GetSmtpdConcurrencyIncoming returns ConcurrencyIncoming
func (c *Config) GetSmtpdConcurrencyIncoming() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdConcurrencyIncoming
}

// GetSmtpdHideReceivedFromAuth returns HideReceivedFromAuth
func (c *Config) GetSmtpdHideReceivedFromAuth() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdHideReceivedFromAuth
}

// GetSmtpdSPFCheck returns SPFCheck
func (c *Config) GetSmtpdSPFCheck() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdSPFCheck
}

// GetSmtpdSPFAction returns SPFAction
func (c *Config) GetSmtpdSPFAction() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.SmtpdSPFAction
}

// GetLaunchDeliverd returns true if deliverd have to be launched
func (c *Config) GetLaunchDeliverd() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LaunchDeliverd
}

// RFC

// return getRFCHeloNeedsFqnOrAddress
func (c *Config) getRFCHeloNeedsFqnOrAddress() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RFCHeloNeedsFqnOrAddress
}

// returns RFCHeloMandatory
func (c *Config) getRFCHeloMandatory() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RFCHeloMandatory
}

// return getRFCMailFromLocalpartSize
func (c *Config) getRFCMailFromLocalpartSize() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RFCMailFromLocalpartSize
}

// nsqd
// GetNsqdEnableLogging return loging enable/disable for nsqd
/*func (c *Config) GetNsqdEnableLogging() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.NsqdEnbleLogging
}*/

// GetNSQLookupdTcpAddresses returns lookupd tcp adresses
func (c *Config) GetNSQLookupdTcpAddresses() (addr []string) {
	if c.cfg.NSQLookupdTcpAddresses == "" {
		return
	}
	c.Lock()
	defer c.Unlock()
	p := strings.Split(c.cfg.NSQLookupdTcpAddresses, ";")
	for _, a := range p {
		addr = append(addr, a)
	}
	return
}

// GetNSQLookupdHttpAddresses returns lookupd HTTP adresses
func (c *Config) GetNSQLookupdHttpAddresses() (addr []string) {
	if c.cfg.NSQLookupdHttpAddresses == "" {
		return
	}
	c.Lock()
	defer c.Unlock()
	p := strings.Split(c.cfg.NSQLookupdHttpAddresses, ";")
	for _, a := range p {
		addr = append(addr, a)
	}
	return
}

// REST server

// GetRestServerLaunch return true if REST server must be launched
func (c *Config) GetRestServerLaunch() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LaunchRestServer
}

// GetRestServerIp return the ip that the REST server should listen on
func (c *Config) GetRestServerIp() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RestServerIp
}

// GetRestServerPort return the port that the REST server should listen on
func (c *Config) GetRestServerPort() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RestServerPort
}

// GetRestServerIsTls return RestServerIsTls
func (c *Config) GetRestServerIsTls() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RestServerIsTls
}

// GetRestServerLogin return RestServerLogin
func (c *Config) GetRestServerLogin() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RestServerLogin
}

// SetRestServerLogin is used to set REST server login
func (c *Config) SetRestServerLogin(login string) {
	c.Lock()
	defer c.Unlock()
	c.cfg.RestServerLogin = login
}

// GetRestServerPasswd return RestServerPasswd
func (c *Config) GetRestServerPasswd() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.RestServerPasswd
}

// SetRestServerPasswd set RestServerPasswd
func (c *Config) SetRestServerPasswd(passwd string) {
	c.Lock()
	defer c.Unlock()
	c.cfg.RestServerPasswd = passwd
}

// deliverd

// GetDeliverdConcurrencyLocal returns DeliverdMaxInFlight
func (c *Config) GetDeliverdConcurrencyLocal() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdConcurrencyLocal
}

// GetDeliverdConcurrencyRemote returns max concurrency for deliverd remote
func (c *Config) GetDeliverdConcurrencyRemote() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdConcurrencyRemote
}

// GetLocalIps returns ordered lits of local IP (net.IP) to use when sending mail
func (c *Config) GetLocalIps() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LocalIps
	/*
		// no mix beetween & and |
		failover := strings.Count(localIps, "&") != 0
		roundRobin := strings.Count(localIps, "|") != 0

		if failover && roundRobin {
			return nil, errors.New("mixing & and | are not allowed in config COCOSMAIL_DELIVERD_LOCAL_IPS")
		}

		var sIps []string

		// one local ip
		if !failover && !roundRobin {
			sIps = append(sIps, localIps)
		} else { // multiple locales ips
			var sep string
			if failover {
				sep = "&"
			} else {
				sep = "|"
			}
			sIps = strings.Split(localIps, sep)
		}

		for _, ipStr := range sIps {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, errors.New("invalid IP " + ipStr + " found in config COCOSMAIL_DELIVERD_LOCAL_IPS")
			}
			lIps = append(lIps, ip)
		}
		return lIps, nil*/
}

// GetDeliverdRemoteTimeout return remote timeout in second
// time to wait for a response from remote server before closing conn
func (c *Config) GetDeliverdRemoteTimeout() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdRemoteTimeout
}

// GetDeliverdQueueLifetime return queue lifetime in minutes
func (c *Config) GetDeliverdQueueLifetime() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdQueueLifetime
}

// GetDeliverdQueueBouncesLifetime return DeliverdQueueBouncesLifetime
func (c *Config) GetDeliverdQueueBouncesLifetime() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdQueueBouncesLifetime
}

// GetDeliverdRemoteTLSFallback return DeliverdRemoteTLSFallback
func (c *Config) GetDeliverdRemoteTLSFallback() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdRemoteTLSFallback
}

// GetDeliverdRemoteUseSameHost return DeliverdRemoteUseSameHost
func (c *Config) GetDeliverdRemoteUseSameHost() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdRemoteUseSameHost
}

// GetDeliverdRemoteTLSSkipVerify return DeliverdRemoteTLSSkipVerify
func (c *Config) GetDeliverdRemoteTLSSkipVerify() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdRemoteTLSSkipVerify
}

// GetDeliverdDkimSign wheras deliverd must sign outgoing (remote) email
func (c *Config) GetDeliverdDkimSign() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DeliverdDkimSign
}

// GetUsersHomeBase returns users home base
func (c *Config) GetUsersHomeBase() string {
	c.Lock()
	defer c.Unlock()
	return AbsPath(c.cfg.UsersHomeBase)
}

// GetUserMailboxDefaultQuota return the default mailbox quota
func (c *Config) GetUserMailboxDefaultQuota() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.UserMailboxDefaultQuota
}

// GetDovecotSupportEnabled returns DovecotSupportEnabled
func (c *Config) GetDovecotSupportEnabled() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LdaType == "dovecot"
}

// GetLdaType returns LdaType
func (c *Config) GetLdaType() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LdaType
}

// GetDovecotLda returns path to dovecot-lda binary
func (c *Config) GetDovecotLda() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.DovecotLda
}

// GetLaunchImap returns true if the IMAP server has to be launched
func (c *Config) GetLaunchImap() bool {
	c.Lock()
	defer c.Unlock()
	return c.cfg.LaunchImap
}

// GetImapDsns returns the IMAP listeners
func (c *Config) GetImapDsns() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.ImapdDsns
}

// GetLaunchPop3 returns true if pop3 has to be launched
func (c *Config) GetLaunchPop3() bool {
	c.Lock()
	r := c.cfg.LaunchPop3
	c.Unlock()
	return r
}

// GetPop3Dsns returns smtpd dsns
func (c *Config) GetPop3Dsns() string {
	c.Lock()
	defer c.Unlock()
	return c.cfg.Pop3dDsns
}

// GetPop3ServerTimeout return pop3TransactionTimeout
func (c *Config) GetPop3ServerTimeout() int {
	c.Lock()
	defer c.Unlock()
	return c.cfg.Pop3dServerTimeout
}
