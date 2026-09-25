package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"
)

// RestartRequest receives why the server must restart to apply settings.
// main restarts gracefully, as the same process (same PID).
var RestartRequest = make(chan string, 1)

// how often settings are checked, and how long they must stay unchanged
// before they're applied: several settings are often changed at once
var (
	settingsCheckInterval = 2 * time.Second
	settingsSettleDelay   = 2 * time.Second
)

// WatchSettings applies settings changed in DB (by cocosmail config): at once
// when possible, else by requesting a restart. Settings are checked every few
// seconds, and at once on SIGHUP.
func WatchSettings() {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	// polling every few seconds would fill the debug log with SQL
	quiet := DB.LogMode(false)
	version := SettingsVersion(quiet)
	for {
		select {
		case <-time.After(settingsCheckInterval):
		case <-hup:
			Logger.Info("SIGHUP: checking settings")
		}
		v := SettingsVersion(quiet)
		if v == version {
			continue
		}
		// wait until settings stop changing, at most 5 times
		for i := 0; i < 5; i++ {
			time.Sleep(settingsSettleDelay)
			next := SettingsVersion(quiet)
			if next == v {
				break
			}
			v = next
		}
		version = v
		if restart := applySettings(); restart != "" {
			select {
			case RestartRequest <- restart:
			default:
			}
			return
		}
	}
}

// applySettings loads settings from DB. Settings that apply live are applied,
// if a setting needs a restart it returns why. Invalid settings are rolled back.
func applySettings() (restart string) {
	values, _, err := CurrentSettings(DB)
	if err != nil {
		Logger.Error("settings: " + err.Error())
		return ""
	}
	current := Cfg.Values()
	changed := changedSettings(current, values)
	if len(changed) == 0 {
		return ""
	}

	var next Config
	err = next.Load(values)
	if err == nil {
		err = next.CheckRequired()
	}
	var restartKeys []string
	for _, key := range changed {
		if s, _ := SettingByKey(key); s.Restart {
			restartKeys = append(restartKeys, key)
		}
	}
	if err == nil && len(restartKeys) > 0 {
		err = preflight(&next, restartKeys)
	}
	if err != nil {
		rollbackSettings(current, changed, err)
		return ""
	}

	names := envNames(changed)
	if len(restartKeys) > 0 {
		Logger.Info("settings changed: " + names + ", restarting to apply")
		return "settings changed: " + names
	}
	if err = Cfg.Load(values); err != nil {
		rollbackSettings(current, changed, err)
		return ""
	}
	Logger.Info("settings applied: " + names)
	return ""
}

// changedSettings returns keys whose value differs, defaults included
func changedSettings(current, values map[string]string) (changed []string) {
	merged := SettingsDefaults()
	for k, v := range values {
		merged[k] = v
	}
	for _, s := range Settings {
		if current[s.Key] != merged[s.Key] {
			changed = append(changed, s.Key)
		}
	}
	return
}

// rollbackSettings puts back the values the server runs with
func rollbackSettings(current map[string]string, changed []string, reason error) {
	old := make(map[string]string)
	for _, key := range changed {
		if s, _ := SettingByKey(key); !s.Bootstrap {
			old[key] = current[key]
		}
	}
	if SettingsManagedBy(DB) != "" || len(old) == 0 {
		Logger.Error("settings not applied: " + reason.Error())
		return
	}
	if err := SettingsToDB(DB, old); err != nil {
		Logger.Error("settings not applied: " + reason.Error() + ". Rollback failed: " + err.Error())
		return
	}
	Logger.Error("settings not applied, previous values restored: " + reason.Error())
}

// preflight checks, before restarting, that the server will start with next.
// A server that doesn't come back can't be fixed remotely.
func preflight(next *Config, keys []string) error {
	changed := make(map[string]bool)
	for _, k := range keys {
		changed[k] = true
	}
	if changed["smtpd_launch"] || changed["smtpd_dsns"] {
		if err := checkListeners(next.GetLaunchSmtpd(), next.GetSmtpdDsns(), "smtp", Cfg.GetSmtpdDsns()); err != nil {
			return errors.New(SettingEnvName("smtpd_dsns") + ": " + err.Error())
		}
	}
	if changed["pop3d_launch"] || changed["pop3d_dsns"] {
		if err := checkListeners(next.GetLaunchPop3(), next.GetPop3Dsns(), "pop3", Cfg.GetPop3Dsns()); err != nil {
			return errors.New(SettingEnvName("pop3d_dsns") + ": " + err.Error())
		}
	}
	if changed["logpath"] {
		if p := next.GetLogPath(); p != "stdout" && p != "discard" {
			f, err := os.OpenFile(path.Join(p, "current.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				return errors.New(SettingEnvName("logpath") + ": " + err.Error())
			}
			f.Close()
		}
	}
	if changed["store_source"] && next.GetStoreDriver() == "disk" {
		if err := os.MkdirAll(diskStorePath(next.GetStoreSource()), 0700); err != nil {
			return errors.New(SettingEnvName("store_source") + ": " + err.Error())
		}
	}
	return nil
}

// checkListeners checks certificates and addresses of listeners in dsns.
// proto is smtp or pop3, running are the listeners of the running server.
func checkListeners(launch bool, dsns, proto, running string) error {
	if !launch {
		return nil
	}
	list, err := GetDsnsFromString(dsns)
	if err != nil {
		return err
	}
	// ports we listen on now are free after restart
	ours := make(map[int]bool)
	if runningList, err := GetDsnsFromString(running); err == nil {
		for _, d := range runningList {
			ours[d.TcpAddr.Port] = true
		}
	}
	for _, d := range list {
		if proto == "pop3" && !d.Ssl && !d.TcpAddr.IP.IsLoopback() {
			return fmt.Errorf("%s: nossl is only allowed on a loopback address for POP3", d.String())
		}
		if d.Ssl {
			crt := path.Join(BaseDir(), "ssl", proto+"-"+d.CertName+".crt")
			key := path.Join(BaseDir(), "ssl", proto+"-"+d.CertName+".key")
			if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
				return fmt.Errorf("%s: certificate: %s", d.String(), err)
			}
		}
		if ours[d.TcpAddr.Port] {
			continue
		}
		l, err := net.Listen("tcp", d.TcpAddr.String())
		if err != nil {
			return fmt.Errorf("%s: %s", d.String(), err)
		}
		l.Close()
	}
	return nil
}

// envNames returns setting keys as environment variable names, sorted
func envNames(keys []string) string {
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = SettingEnvName(k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
