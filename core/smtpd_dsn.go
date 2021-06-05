package core

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// DSN IP port and secured (none, tls, ssl)
type Dsn struct {
	TcpAddr net.TCPAddr
	Ssl     bool
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
	// clean
	dsnsStr = strings.ToLower(dsnsStr)

	// parse
	for _, dsnStr := range strings.Split(dsnsStr, ";") {
		if strings.Count(dsnStr, ":") != 2 {
			return dsns, errors.New("bad smtpd.dsn " + dsnStr + " found in config" + dsnsStr)
		}
		t := strings.Split(dsnStr, ":")
		// ip & port valid ?
		tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(t[0], t[1]))
		if err != nil {
			return dsns, errors.New("bad IP:Port found in dsn" + dsnStr + "from config dsn" + dsnsStr)
		}
		ssl, err := strconv.ParseBool(t[2])
		if err != nil {
			return dsns, ErrBadDsn(err)
		}
		dsns = append(dsns, Dsn{*tcpAddr, ssl})
	}
	return
}
