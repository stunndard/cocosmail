package core

import (
	"errors"
	"strings"
)

var errBadAddress = errors.New("invalid address")

// parseReversePath parses the address of MAIL FROM: <local@domain>, or <>
// for the null sender. The brackets may be left out (some clients do), but
// not only one of them. A source route (<@a,@b:user@domain>) is dropped
// (RFC 5321 4.1.2).
func parseReversePath(path string) (string, error) {
	if strings.HasPrefix(path, "<") || strings.HasSuffix(path, ">") {
		if len(path) < 2 || path[0] != '<' || path[len(path)-1] != '>' {
			return "", errBadAddress
		}
		path = path[1 : len(path)-1]
	}
	if path == "" {
		return "", nil
	}
	if path[0] == '@' {
		i := strings.IndexByte(path, ':')
		if i < 0 {
			return "", errBadAddress
		}
		path = path[i+1:]
	}
	if err := checkMailbox(path); err != nil {
		return "", err
	}
	return path, nil
}

// checkMailbox checks the syntax of an address local@domain (RFC 5321 4.1.2),
// UTF-8 allowed (RFC 6531)
func checkMailbox(addr string) error {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return errBadAddress
	}
	local, domain := addr[:i], addr[i+1:]
	if !validLocalPart(local) || !validMailDomain(domain) {
		return errBadAddress
	}
	return nil
}

func validLocalPart(s string) bool {
	if strings.HasPrefix(s, `"`) {
		return validQuotedString(s)
	}
	return validDotAtom(s)
}

// atext of RFC 5322, and UTF-8
func isAtext(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0 || c >= 0x80
}

// atom *("." atom)
func validDotAtom(s string) bool {
	if s == "" {
		return false
	}
	for _, atom := range strings.Split(s, ".") {
		if atom == "" {
			return false
		}
		for j := 0; j < len(atom); j++ {
			if !isAtext(atom[j]) {
				return false
			}
		}
	}
	return true
}

// "..." with printable characters, \ escapes any of them
func validQuotedString(s string) bool {
	if len(s) < 3 || s[len(s)-1] != '"' {
		return false
	}
	for j := 1; j < len(s)-1; j++ {
		c := s[j]
		switch {
		case c == '\\':
			j++
			if j == len(s)-1 || s[j] < ' ' || s[j] == 0x7f {
				return false
			}
		case c == '"' || c < ' ' || c == 0x7f:
			return false
		}
	}
	return true
}

// a hostname, or an address literal [192.0.2.1] / [IPv6:2001:db8::1]
func validMailDomain(s string) bool {
	if strings.HasPrefix(s, "[") {
		if len(s) < 3 || s[len(s)-1] != ']' {
			return false
		}
		for j := 1; j < len(s)-1; j++ {
			if c := s[j]; c == '[' || c == ']' || c == '\\' || c <= ' ' || c >= 0x7f {
				return false
			}
		}
		return true
	}
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c >= 0x80) {
				return false
			}
		}
	}
	return true
}
