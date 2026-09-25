package core

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net"
	"path"
	"strings"
	"time"
)

// RemoveBrackets removes trailing and ending brackets (<string> -> string)
func RemoveBrackets(s string) string {
	if strings.HasPrefix(s, "<") {
		s = s[1:]
	}
	if strings.HasSuffix(s, ">") {
		s = s[0 : len(s)-1]
	}
	return s
}

// Check if a string is in a Slice of string
// TODO: replace by sort package
func IsStringInSlice(str string, s []string) (found bool) {
	found = false
	for _, t := range s {
		if t == str {
			found = true
			break
		}
	}
	return
}

// StripQuotes remove trailing and ending "
func StripQuotes(s string) string {
	if s == "" {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// IsIPV4 return true if ip is ipV4
func IsIPV4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// AddrIP returns the IP of a network address, without IPv6 zone
// (fe80::1%eth0 -> fe80::1). Returns nil if there is no IP.
func AddrIP(addr net.Addr) net.IP {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	if i := strings.Index(host, "%"); i != -1 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

// isAddressLiteral returns true if s is an IP address, either bare or as
// an RFC 5321 address literal: [192.0.2.1] or [IPv6:2001:db8::1]
func isAddressLiteral(s string) bool {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
		if len(s) > 5 && strings.EqualFold(s[:5], "IPv6:") {
			s = s[5:]
		}
	}
	return net.ParseIP(s) != nil
}

// ParseIPAndName parses a local IP entry "IP" or "IP:hostname".
// IPv6 addresses must be enclosed in brackets when followed by a hostname:
// "[2001:db8::1]:mail.example.com". A bare IPv6 address "2001:db8::1" is also accepted.
// name is empty if there is no hostname.
func ParseIPAndName(s string) (ip net.IP, name string, err error) {
	s = strings.TrimSpace(s)
	ipStr := s
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 {
			return nil, "", errors.New("missing ] in " + s)
		}
		ipStr = s[1:end]
		rest := s[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return nil, "", errors.New("expected : after ] in " + s)
			}
			name = rest[1:]
		}
	} else if net.ParseIP(s) == nil {
		if i := strings.LastIndex(s, ":"); i != -1 {
			ipStr, name = s[:i], s[i+1:]
		}
	}
	ip = net.ParseIP(ipStr)
	if ip == nil {
		return nil, "", errors.New("invalid IP " + ipStr + " in " + s)
	}
	return ip, name, nil
}

// Unix2dos replace all line ending from \n to \r\n
func Unix2dos(ch *[]byte) (err error) {
	dos := bytes.NewBuffer([]byte{})
	var prev byte
	prev = 0
	for _, b := range *ch {
		if b == 10 && prev != 13 {
			if _, err = dos.Write([]byte{13, 10}); err != nil {
				return
			}

		} else {
			if err = dos.WriteByte(b); err != nil {
				return
			}
		}
		prev = b
	}
	*ch, err = ioutil.ReadAll(dos)
	return nil
}

// isFQN checks if domain is FQN (MX or A record)
func isFQN(host string) (bool, error) {
	_, err := net.LookupMX(host)
	if err != nil {
		// Try A
		_, err = net.LookupHost(host)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// This returns current date in a format used by RFC822
// in email headers
func Format822Date() string {
	return time.Now().Format(Time822)
}

// GetBoltFile returns bolt file path
func GetBoltFilePath() string {
	return path.Join(Cfg.GetBasePath(), "bolt/bolt.db")
}
