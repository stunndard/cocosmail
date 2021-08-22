package fail2ban

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stunndard/cocosmail/core"
)

type IpData struct {
	Added    time.Time
	Banned   bool
	Attempts int
	Expires  time.Time
}

const (
	FAILEDAUTH = 2
	BANTIME    = 24 * 7
	KEEPTIME   = 24 * 14
)

var ips = make(map[string]*IpData)

// initialize() is called when a new SMTP session is established.
// Use it to initialize any context required for plugin.
// Return error if there is any problem. In that case, the plugin
// won't be registered and used.
func initialize() error {
	return nil
}

// connect() is called when a new client connects to smtpd session.
// Return done if no more processing should be done by the host
// and proceed to next phase in the SMTP session. Otherwise,
// the host will also do its own processing after calling this hook.
// Return drop to terminate the SMTP client session immediately.
// Return err to signalize an error to the host.
func connect(s *core.SMTPServerSession) (done, drop bool, err error) {
	jsn, err := core.PluginLoadObject("ban", "ips")
	if err != nil {
		return false, false, err
	}
	if len(jsn) > 0 {
		err = json.Unmarshal(jsn, &ips)
		if err != nil {
			return false, false, err
		}
	}
	s.LogDebug(fmt.Sprintf("ip object loaded, %d IPs total", len(ips)))

	// let's do housekeeping
	deleted := 0
	for k, ip := range ips {
		if ip.Added.Add(KEEPTIME * time.Hour).Before(time.Now()) {
			delete(ips, k)
			deleted++
		}
	}
	if deleted > 0 {
		s.LogDebug(fmt.Sprintf("ip object cleaned up, %d IPs deleted", deleted))
	}
	jsn, _ = json.Marshal(ips)
	err = core.PluginSaveObject("ban", "ips", jsn)
	if err != nil {
		return false, false, err
	}

	// get ip
	remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())
	ip, ok := ips[remoteIP]
	if !ok {
		// ip not found
		return false, false, nil
	}
	s.LogDebug(fmt.Sprintf("ip: %s", remoteIP))
	// check the ip
	if !ip.Banned {
		// ip there, but not banned (yet)
		return false, false, nil
	}
	s.LogDebug("ip is BANNED")
	// time to unban?
	if ip.Expires.Before(time.Now()) {
		ip.Banned = false
		ip.Attempts = 0
		delete(ips, remoteIP)
		jsn, _ := json.Marshal(ips)
		err = core.PluginSaveObject("ban", "ips", jsn)
		s.LogDebug("ip is UNBANNED")
		// allow access
		return false, false, err
	}
	// sorry, reban
	/*
	   ip.Expires = time.Now().Add(24 * 3 * time.Hour)
	   jsn, _ = json.Marshal(ips)
	   err = core.PluginSaveObject("ban", "ips", jsn)
	*/
	// drop connection
	return false, true, nil
}

// auth() is called with the result of AUTH command processed by the host.
// user: username used in AUTH command.
// pass: password used in AUTH command.
// success: true if AUTH was successful, false otherwise.
func auth(user, pass string, success bool, s *core.SMTPServerSession) error {
	if success {
		return nil
	}
	remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())
	s.LogDebug(fmt.Sprintf("auth failed: ip: %s user: %s pass: %s", remoteIP, user, pass))

	_, err := checkAndBan(s)
	return err
}

func checkAndBan(s *core.SMTPServerSession) (banned bool, err error) {
	remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())

	var ip *IpData
	var ok bool
	ip, ok = ips[remoteIP]
	if !ok {
		ip = &IpData{
			Added: time.Now(),
		}
	}
	ip.Attempts++
	if !ip.Banned && ip.Attempts >= FAILEDAUTH {
		// ban
		ip.Banned = true
		ip.Expires = time.Now().Add(BANTIME * time.Hour)
		s.LogDebug(fmt.Sprintf("banned ip: %s", remoteIP))
		banned = true
	}
	// update ip
	ips[remoteIP] = ip

	jsn, _ := json.Marshal(ips)
	//s.LogDebug(fmt.Sprintf("json: %s", jsn))
	return banned, core.PluginSaveObject("ban", "ips", jsn)
}

// helo is() called on HELO/EHLO command.
// Return done if no more processing should be done by the host
// and proceed to next phase in the SMTP session. Otherwise,
// the host will also do its own processing after calling this hook.
// Return drop to terminate the SMTP client session immediately.
// Return err to signalize an error to the host.
func helo(s *core.SMTPServerSession) (done, drop bool, err error) {
	heloCmd := strings.ToLower(string(s.GetLastClientCmd()))
	s.LogDebug(fmt.Sprintf("helo received: %s", heloCmd))

	if heloCmd == "ehlo user" {
		drop, err = checkAndBan(s)
	}
	if heloCmd == "ehlo example.com" {
		drop, err = checkAndBan(s)
	}

	return false, drop, err
}

// notify() is called AFTER each SMTP command is done processing by the host.
// Session object contains all relevant data set by the host, for example s.SMTPResponseCode.
// The plugin can act accordingly on every command.
// smtpCommand: the last command sent by the client and processed by the host
// Return drop to terminate the SMTP client session immediately.
// Return err to signalize an error to the host.
func notify(s *core.SMTPServerSession) (drop bool, err error) {
	rcptTo := strings.HasPrefix(strings.ToLower(string(s.GetLastClientCmd())), "rcpt to")
	if rcptTo && s.SMTPResponseCode == 554 {
		//remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())
		//s.LogDebug(fmt.Sprintf("ip %s was denied to relay", remoteIP))
		drop, err = checkAndBan(s)
	}
	if s.SMTPResponseCode == 502 {
		drop, err = checkAndBan(s)
	}

	return drop, err
}

func mailpre(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func mailpost(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func rcptto(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func data(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func beforequeue(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func quit(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func exitasap(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}
