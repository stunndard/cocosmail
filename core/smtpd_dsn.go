package core

import (
	"errors"
	"net"
	"strings"
)

// DSN IP port and secured (none, tls, ssl)
type Dsn struct {
	TcpAddr    net.TCPAddr
	Ssl        bool
	SystemName string
	CertName   string
}

// String return string representation of a dsn
func (d *Dsn) String() string {
	s := ""
	if d.Ssl {
		s = " SSL"
	}
	return d.TcpAddr.String() + s
}

//getDsnsFromString Get dsn string from config and returns slice of dsn struct
func GetDsnsFromString(dsnsStr string) (dsns []Dsn, err error) {
	if len(dsnsStr) == 0 {
		return dsns, errors.New("your smtpd.dsn string is empty")
	}

	// parse
	// a dsn is IP:PORT:HOSTNAME:SSL:CERT
	// IP may be an IPv6 address, preferably enclosed in brackets: [::1]:25:...
	// so the last 4 fields are taken from the right and everything before is the IP
	for _, dsnStr := range strings.Split(dsnsStr, ";") {
		dsnStr = strings.TrimSpace(dsnStr)
		if strings.Count(dsnStr, ":") < 4 {
			return dsns, errors.New("bad dsn " + dsnStr + " found in config " + dsnsStr)
		}
		fields := SplitDsn(dsnStr)
		// IP is not lowercased: an IPv6 zone (fe80::1%eth0) is an interface name
		t := []string{fields.IP, fields.Port, strings.ToLower(fields.Hostname), strings.ToLower(fields.SSL), strings.ToLower(fields.Cert)}
		// ip & port valid ?
		tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(t[0], t[1]))
		if err != nil {
			return dsns, errors.New("bad IP:Port found in dsn " + dsnStr + " from config " + dsnsStr)
		}
		sysName := t[2]
		if sysName == "" {
			return dsns, errors.New("empty system name found in dsn " + dsnStr + " from config " + dsnsStr)
		}
		var ssl bool
		switch t[3] {
		case "ssl":
			ssl = true
		case "nossl":
			ssl = false
		default:
			return dsns, errors.New("bad SSL field \"" + t[3] + "\" in dsn " + dsnStr + ", must be ssl or nossl")
		}
		certName := t[4]
		if certName == "" {
			return dsns, errors.New("empty cert name found in dsn " + dsnStr + " from config " + dsnsStr)
		}

		dsns = append(dsns, Dsn{
			TcpAddr:    *tcpAddr,
			Ssl:        ssl,
			SystemName: sysName,
			CertName:   certName,
		})
	}
	return
}

// DsnFields are the parts of a dsn IP:PORT:HOSTNAME:SSL:CERT, as written
type DsnFields struct {
	// IP without brackets, "" for all addresses
	IP       string
	Port     string
	Hostname string
	// SSL is "ssl" or "nossl"
	SSL  string
	Cert string
}

// SplitDsn splits one dsn in its fields, without checking them. The last 4
// fields are taken from the right, the IP is what's before, IPv6 in brackets
// or not.
func SplitDsn(dsn string) (d DsnFields) {
	f := strings.Split(strings.TrimSpace(dsn), ":")
	n := len(f)
	if n < 5 {
		return DsnFields{IP: strings.TrimSpace(dsn)}
	}
	ip := strings.Join(f[:n-4], ":")
	if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
		ip = ip[1 : len(ip)-1]
	}
	return DsnFields{IP: ip, Port: f[n-4], Hostname: f[n-3], SSL: f[n-2], Cert: f[n-1]}
}

// String joins the fields in a dsn, with IPv6 in brackets
func (d DsnFields) String() string {
	ip := d.IP
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return strings.Join([]string{ip, d.Port, d.Hostname, d.SSL, d.Cert}, ":")
}
