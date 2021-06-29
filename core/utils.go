package core

import (
	"bytes"
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
// todo: refactor
func IsIPV4(ip string) bool {
	if len(ip) > 15 {
		return false
	}
	return true
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
