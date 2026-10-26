package imap

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// longer lines are cut in the log
const maxLogLine = 1000

// protoLog logs one side of an IMAP session, line by line, like smtpd and
// pop3d in debug: "< " what the client sends, "> " what the server sends.
// Literals (message contents) are logged by their size only, passwords are
// masked.
type protoLog struct {
	mu     sync.Mutex
	dir    string // "< " or "> "
	client bool
	log    func(string)

	line      []byte // the line so far, at most maxLogLine bytes
	tail      []byte // its last bytes, for a literal at the end of a cut line
	truncated bool

	literal, literalSize int64 // literal data still to come, and its size
	afterLiteral         bool  // the line goes on after a literal
	// client: the next line is the password of LOGIN, or a SASL response
	maskNext int
}

const (
	maskNone = iota
	maskPassword
	maskSASL
)

func (l *protoLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		if l.literal > 0 {
			k := l.literal
			if int64(len(p)) < k {
				k = int64(len(p))
			}
			l.literal -= k
			p = p[k:]
			if l.literal == 0 {
				l.log(fmt.Sprintf("%s(literal, %d bytes)", l.dir, l.literalSize))
				l.afterLiteral = true
			}
			continue
		}
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			l.add(p)
			break
		}
		l.add(p[:i])
		p = p[i+1:]
		l.flush()
	}
	return n, nil
}

func (l *protoLog) add(b []byte) {
	if room := maxLogLine - len(l.line); room < len(b) {
		l.line = append(l.line, b[:max(room, 0)]...)
		l.truncated = true
	} else {
		l.line = append(l.line, b...)
	}
	const tailSize = 32
	l.tail = append(l.tail, b...)
	if len(l.tail) > tailSize {
		l.tail = append(l.tail[:0], l.tail[len(l.tail)-tailSize:]...)
	}
}

// a literal follows the line: {123}, {123+} (LITERAL+), ~{123} (BINARY)
var literalRe = regexp.MustCompile(`~?\{(\d+)\+?\}$`)

func literalAt(line string) (int64, bool) {
	m := literalRe.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	return n, err == nil
}

func (l *protoLog) flush() {
	line := strings.TrimSuffix(string(l.line), "\r")
	size, isLiteral := literalAt(strings.TrimSuffix(string(l.tail), "\r"))
	if l.truncated {
		line += " ..."
		if isLiteral {
			line += fmt.Sprintf(" {%d}", size)
		}
	}
	if l.client {
		line = l.mask(line, isLiteral)
	}
	// the CRLF ending a command after its literal says nothing
	if line != "" || !l.afterLiteral {
		l.log(l.dir + line)
	}
	l.line, l.tail, l.truncated, l.afterLiteral = l.line[:0], l.tail[:0], false, false
	if isLiteral && size > 0 {
		l.literal, l.literalSize = size, size
	}
}

// mask hides passwords in what the client sends
func (l *protoLog) mask(line string, isLiteral bool) string {
	switch l.maskNext {
	case maskPassword:
		// rest of LOGIN after a username literal: the password, or the
		// size of its literal
		l.maskNext = maskNone
		if isLiteral {
			return line
		}
		return " ********"
	case maskSASL:
		l.maskNext = maskNone
		return maskPlain(line)
	}
	f := strings.SplitN(line, " ", 3)
	if len(f) < 3 {
		return line
	}
	switch strings.ToUpper(f[1]) {
	case "LOGIN":
		user, rest := splitUsername(f[2])
		if rest == "" {
			if isLiteral {
				// username literal, the password comes after it
				l.maskNext = maskPassword
			}
			return line
		}
		if _, ok := literalAt(rest); ok {
			return line
		}
		return f[0] + " " + f[1] + " " + user + " ********"
	case "AUTHENTICATE":
		mech := strings.SplitN(f[2], " ", 2)
		if len(mech) == 1 {
			// no initial response, it comes on the next line
			l.maskNext = maskSASL
			return line
		}
		if mech[1] == "=" {
			return line
		}
		if strings.EqualFold(mech[0], "PLAIN") {
			return f[0] + " " + f[1] + " " + mech[0] + " " + maskPlain(mech[1])
		}
		return f[0] + " " + f[1] + " " + mech[0] + " ********"
	}
	return line
}

// splitUsername splits the arguments of LOGIN after the username, an atom
// or a quoted string
func splitUsername(args string) (user, rest string) {
	if strings.HasPrefix(args, `"`) {
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case '\\':
				i++
			case '"':
				return args[:i+1], args[i+1:]
			}
		}
		return args, ""
	}
	if i := strings.IndexByte(args, ' '); i >= 0 {
		return args[:i], args[i:]
	}
	return args, ""
}

// maskPlain shows the username of an AUTHENTICATE PLAIN response
// (authzid\0authcid\0passwd), not the password
func maskPlain(encoded string) string {
	if encoded == "*" {
		return encoded // cancelled
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "********"
	}
	t := bytes.Split(decoded, []byte{0})
	if len(t) != 3 {
		return "********"
	}
	if len(t[0]) > 0 {
		return string(t[0]) + " " + string(t[1]) + " ********"
	}
	return string(t[1]) + " ********"
}
