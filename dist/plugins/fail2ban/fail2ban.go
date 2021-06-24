package fail2ban

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/stunndard/cocosmail/core"
)

type IpData struct {
	Banned   bool
	Attempts int
	Expires  time.Time
}

const (
	FAILEDAUTH = 2
	BANTIME = 24 * 7
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
// Return err to signalize an error to the host
func connect(s *core.SMTPServerSession) (done, drop bool, err error) {
	jsn, err := core.PluginLoadObject("ban", "ips")
	if err != nil {
		return false, false, err
	}

	err = json.Unmarshal(jsn, &ips)
	if err != nil {
		return false, false, err
	}
	s.LogDebug(fmt.Sprintf("ip object loaded, %d", len(ips)))

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

// auth is called with the result of AUTH command processed by the host.
// user: username used in AUTH command.
// pass: password used in AUTH command.
// success: true if AUTH was successful, false otherwise
func auth(user, pass string, success bool, s *core.SMTPServerSession) error {
	if success {
		return nil
	}
	remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())
	s.LogDebug(fmt.Sprintf("auth failed: ip: %s user: %s pass: %s", remoteIP, user, pass))

	var ip *IpData
	var ok bool
	ip, ok = ips[remoteIP]
	if !ok {
		ip = &IpData{}
	}
	ip.Attempts++
	if !ip.Banned && ip.Attempts >= FAILEDAUTH {
		// ban
		ip.Banned = true
		ip.Expires = time.Now().Add(BANTIME * time.Hour)
		s.LogDebug(fmt.Sprintf("banned ip: %s", remoteIP))
	}
	// update ip
	ips[remoteIP] = ip

	jsn, _ := json.Marshal(ips)
	s.LogDebug(fmt.Sprintf("json: %s", jsn))
	return core.PluginSaveObject("ban", "ips", jsn)
}

