package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/stunndard/cocosmail/message"
	"github.com/traefik/yaegi/interp"
	"golang.org/x/crypto/bcrypt"
)

const (
	// CR is a Carriage Return
	CR = 13
	// LF is a Line Feed
	LF = 10
	// MAXTOTALHEADERSIZE Max total size of headers in a message
	MAXTOTALHEADERSIZE = 64 * 1024
)

type YagPlugin struct {
	Yag  *interp.Interpreter
	Name string
}

// SMTPServerSession retpresents a SMTP session (server)
type SMTPServerSession struct {
	uuid             string
	Conn             net.Conn
	connTLS          *tls.Conn
	systemName       string
	certName         string
	YagPlugins       []YagPlugin
	timer            *time.Timer // for timeout
	timeout          time.Duration
	tls              bool
	tlsVersion       string
	RelayGranted     bool
	user             *User
	seenHelo         bool
	seenMail         bool
	lastClientCmd    []byte
	helo             string
	Envelope         message.Envelope
	LastRcptTo       string
	rcptCount        int
	BadRcptToCount   int
	vrfyCount        int
	remoteAddr       string
	SMTPResponseCode uint32
	dataBytes        uint64
	startAt          time.Time
	exiting          bool
	CurrentRawMail   []byte
}

// NewSMTPServerSession returns a new SMTP session
func NewSMTPServerSession(conn net.Conn, dsn Dsn) (*SMTPServerSession, error) {

	s := &SMTPServerSession{
		systemName:     dsn.SystemName,
		certName:       dsn.CertName,
		startAt:        time.Now(),
		Conn:           conn,
		remoteAddr:     conn.RemoteAddr().String(),
		RelayGranted:   false,
		rcptCount:      0,
		BadRcptToCount: 0,
		vrfyCount:      0,
		lastClientCmd:  []byte{},
		seenHelo:       false,
		seenMail:       false,
		// session timeout
		timeout: time.Duration(Cfg.GetSmtpdServerTimeout()) * time.Second,
	}
	s.timer = time.AfterFunc(s.timeout, s.raiseTimeout)

	var err error
	s.uuid, err = NewUUID()
	if err != nil {
		return nil, err
	}

	if dsn.Ssl {
		s.connTLS = conn.(*tls.Conn)
		s.tls = true
	}

	return s, nil
}

// GetLastClientCmd returns lastClientCmd (not splited)
func (s *SMTPServerSession) GetLastClientCmd() []byte {
	return bytes.TrimSuffix(s.lastClientCmd, []byte{13})
}

// GetEnvelope returns pointer to current envelope
// mainly used for plugin
func (s *SMTPServerSession) GetEnvelope() *message.Envelope {
	return &s.Envelope
}

// timeout
func (s *SMTPServerSession) raiseTimeout() {
	s.Log("client timeout")
	s.Out(420, "Client timeout")
	s.ExitAsap()
}

// recoverOnPanic handles panic
func (s *SMTPServerSession) recoverOnPanic() {
	if err := recover(); err != nil {
		s.LogError(fmt.Sprintf("PANIC: %s - Stack: %s", err.(error).Error(), debug.Stack()))
		s.Out(421, "sorry I have an emergency")
		s.ExitAsap()
	}
}

// ExitAsap exits session as soon as possible
func (s *SMTPServerSession) ExitAsap() {
	//s.Log("exitasap() enter")
	//defer s.Log("exitasap() done")

	s.timer.Stop()

	if s.exiting {
		time.Sleep(time.Duration(1) * time.Millisecond)
		return
	}
	s.exiting = true

	// Plugins
	ExecSMTPdPlugins("exitasap", s)
	_ = s.Conn.Close()
}

// resetTimeout reset timeout
func (s *SMTPServerSession) resetTimeout() {
	s.timer.Stop()
	s.timer.Reset(s.timeout)
}

// Reset session
func (s *SMTPServerSession) Reset() {
	s.Envelope.MailFrom = ""
	s.seenMail = false
	s.Envelope.RcptTo = []string{}
	s.rcptCount = 0
	s.CurrentRawMail = []byte{}
	s.resetTimeout()
}

// Out : to client
func (s *SMTPServerSession) Out(code uint32, msg string) {
	if !s.exiting {
		// _, _ = s.Conn.Write([]byte(msg + "\r\n"))
		_, _ = s.Conn.Write([]byte(fmt.Sprintf("%d %s\r\n", code, msg)))
		s.SMTPResponseCode = code
		s.LogDebug(fmt.Sprintf("> %d %s", code, msg))
		s.resetTimeout()
	}
}

// OutMulti : to client
func (s *SMTPServerSession) OutMulti(code uint32, msg string) {
	if !s.exiting {
		// _, _ = s.Conn.Write([]byte(msg + "\r\n"))
		_, _ = s.Conn.Write([]byte(fmt.Sprintf("%d-%s\r\n", code, msg)))
		s.SMTPResponseCode = code
		s.LogDebug(fmt.Sprintf("> %d-%s", code, msg))
		s.resetTimeout()
	}
}

// Log helper for INFO log
func (s *SMTPServerSession) Log(msg ...string) {
	Logger.Info("smtpd ", s.uuid, "-", s.Conn.RemoteAddr().String(), "-", strings.Join(msg, " "))
}

// LogError is a log helper for ERROR logs
func (s *SMTPServerSession) LogError(msg ...string) {
	Logger.Error("smtpd ", s.uuid, "-", s.Conn.RemoteAddr().String(), "-", strings.Join(msg, " "))
}

// LogDebug is a log helper for DEBUG logs
func (s *SMTPServerSession) LogDebug(msg ...string) {
	if !Cfg.GetDebugEnabled() {
		return
	}
	Logger.Debug("smtpd -", s.uuid, "-", s.Conn.RemoteAddr().String(), "-", strings.Join(msg, " "))
}

// LF withour CR
func (s *SMTPServerSession) strayNewline() {
	s.Log("LF not preceded by CR")
	s.Out(451, "You sent me LF not preceded by a CR, your SMTP client is broken.")
}

// purgeConn Purge connection buffer
func (s *SMTPServerSession) purgeConn() (err error) {
	ch := make([]byte, 1)
	for {
		_, err = s.Conn.Read(ch)
		if err != nil {
			return
		}
		/*if ch[0] == 10 {
			break
		}*/
	}
}

// add pause (ex if client seems to be illegitime)
func (s *SMTPServerSession) pause(seconds int) {
	time.Sleep(time.Duration(seconds) * time.Second)
}

// smtpGreeting Greeting
func (s *SMTPServerSession) smtpGreeting() {
	defer s.recoverOnPanic()
	// TODO: verify if there's some data in the buffer
	time.Sleep(100 * time.Nanosecond)
	if int(SmtpSessionsCount) > Cfg.GetSmtpdConcurrencyIncoming() {
		s.Log(fmt.Sprintf("GREETING - max connections reached %d/%d", SmtpSessionsCount,
			Cfg.GetSmtpdConcurrencyIncoming()))
		s.Out(421, fmt.Sprintf("sorry, the maximum number of connections has been reached, try again later %s",
			s.uuid))
		s.ExitAsap()
		return
	}
	s.Log(fmt.Sprintf("starting new transaction %d/%d", SmtpSessionsCount, Cfg.GetSmtpdConcurrencyIncoming()))

	// Plugins
	done, drop := ExecSMTPdPlugins("connect", s)
	if done || drop {
		if drop {
			s.Log("plugin terminating session")
			s.ExitAsap()
			return
		}
		return
	}

	greeting := s.systemName + " ESMTP " + s.uuid
	if !Cfg.GetHideServerSignature() {
		greeting += " - cocosmail " + Version
	}
	s.Out(220, greeting)
	if s.tls {
		s.Log("secured via " + tlsGetVersion(s.connTLS.ConnectionState().Version) + " " + tlsGetCipherSuite(s.connTLS.ConnectionState().CipherSuite))
	}
}

// EHLO HELO
// helo do the common EHLO/HELO tasks
func (s *SMTPServerSession) heloBase(msg []string) (cont bool) {
	defer s.recoverOnPanic()
	if s.seenHelo {
		s.Log("helo/ehlo already received")
		s.pause(1)
		s.Out(503, "bad sequence, EHLO|HELO already recieved")
		return false
	}

	// Plugins
	done, drop := ExecSMTPdPlugins("helo", s)
	if done || drop {
		if drop {
			s.Log("plugin terminating session")
			s.ExitAsap()
			return false
		}
		s.seenHelo = true
		return true
	}

	s.helo = ""
	if len(msg) > 1 {
		if Cfg.getRFCHeloNeedsFqnOrAddress() {
			// if it's not an address check for fqn
			if net.ParseIP(msg[1]) == nil {
				ok, err := isFQN(msg[1])
				if err != nil {
					s.Log("fail to do lookup on helo host. " + err.Error())
					s.pause(2)
					s.Out(404, "unable to resolve "+msg[1]+". Need fqdn or address in helo command")
					return false
				}
				if !ok {
					s.Log("helo command rejected, need fully-qualified hostname or address" + msg[1] + " given")
					s.pause(2)
					s.Out(504, "5.5.2 helo command rejected, need fully-qualified hostname or address")
					return false
				}
			}
		}
		s.helo = strings.Join(msg[1:], " ")
	} else if Cfg.getRFCHeloNeedsFqnOrAddress() {
		s.Log("helo command rejected, need fully-qualified hostname. None given")
		s.pause(2)
		s.Out(504, "5.5.2 helo command rejected, need fully-qualified hostname or address")
		return false
	}
	s.seenHelo = true
	return true
}

// HELO
func (s *SMTPServerSession) smtpHelo(msg []string) {
	defer s.recoverOnPanic()
	if s.heloBase(msg) {
		s.Out(250, fmt.Sprintf("%s", s.systemName))
	}
}

// EHLO
func (s *SMTPServerSession) smtpEhlo(msg []string) {
	defer s.recoverOnPanic()
	if s.heloBase(msg) {
		s.OutMulti(250, fmt.Sprintf("%s", s.systemName))
		// Extensions
		// Size
		s.OutMulti(250, fmt.Sprintf("SIZE %d", Cfg.GetSmtpdMaxDataBytes()))
		if !s.tls {
			// no auth is allowed over non-secure coonection
			s.Out(250, "STARTTLS")
		} else {
			// s.Out(250, "AUTH LOGIN PLAIN CRAM-MD5")
			s.Out(250, "AUTH LOGIN PLAIN")
		}
	}
}

// MAIL FROM
func (s *SMTPServerSession) smtpMailFrom(msg []string) {
	defer s.recoverOnPanic()
	var extension []string

	// Reset
	s.Reset()

	// cmd EHLO ?
	if Cfg.getRFCHeloMandatory() && !s.seenHelo {
		s.pause(2)
		s.Out(503, "5.5.2 Send hello first")
		return
	}
	msgLen := len(msg)
	// mail from ?
	if msgLen == 1 || !strings.HasPrefix(strings.ToLower(msg[1]), "from:") || msgLen > 4 {
		s.Log(fmt.Sprintf("MAIL - Bad syntax: %s", strings.Join(msg, " ")))
		s.pause(2)
		s.Out(501, "5.5.4 Syntax: MAIL FROM:<address> [SIZE]")
		return
	}

	// Plugin - hook "mailpre"
	_, drop := ExecSMTPdPlugins("mailpre", s)
	if drop {
		s.Log("plugin terminating session")
		s.ExitAsap()
		return
	}

	// mail from:<user> EXT || mail from: <user> EXT
	if len(msg[1]) > 5 { // mail from:<user> EXT
		t := strings.Split(msg[1], ":")
		s.Envelope.MailFrom = t[1]
		if msgLen > 2 {
			extension = append(extension, msg[2:]...)
		}
	} else if msgLen > 2 { // mail from: user EXT
		s.Envelope.MailFrom = msg[2]
		if msgLen > 3 {
			extension = append(extension, msg[3:]...)
		}
	} else { // null sender
		s.Envelope.MailFrom = ""
	}

	// Extensions size
	if len(extension) != 0 {
		// Only SIZE is supported (and announced)
		if len(extension) > 1 {
			s.Log(fmt.Sprintf("MAIL - Bad syntax: %s", strings.Join(msg, " ")))
			s.pause(2)
			s.Out(501, "5.5.4 Syntax: MAIL FROM:<address> [SIZE]")
			return
		}
		// SIZE
		extValue := strings.Split(extension[0], "=")
		if len(extValue) != 2 {
			s.Log(fmt.Sprintf("MAIL FROM - Bad syntax : %s ", strings.Join(msg, " ")))
			s.pause(2)
			s.Out(501, "5.5.4 Syntax: MAIL FROM:<address> [SIZE]")
			return
		}
		if strings.ToLower(extValue[0]) != "size" {
			s.Log(fmt.Sprintf("MAIL FROM - Unsuported extension : %s ", extValue[0]))
			s.pause(2)
			s.Out(501, "5.5.4 Invalid arguments")
			return
		}
		if Cfg.GetSmtpdMaxDataBytes() != 0 {
			size, err := strconv.ParseUint(extValue[1], 10, 64)
			if err != nil {
				s.Log(fmt.Sprintf("MAIL FROM - bad value for size extension SIZE=%v", extValue[1]))
				s.pause(2)
				s.Out(501, "5.5.4 Invalid arguments")
				return
			}
			if size > Cfg.GetSmtpdMaxDataBytes() {
				s.Log(fmt.Sprintf("MAIL FROM - message exceeds fixed maximum message size %d/%d", size,
					Cfg.GetSmtpdMaxDataBytes()))
				s.Out(552, "message exceeds fixed maximum message size")
				s.pause(1)
				return
			}
		}
	}

	// remove <>
	s.Envelope.MailFrom = RemoveBrackets(s.Envelope.MailFrom)

	// mail from is valid ?
	reversePathlen := len(s.Envelope.MailFrom)
	if reversePathlen > 0 { // 0 -> null reverse path (bounce)
		if reversePathlen > 256 { // RFC 5321 4.3.5.1.3
			s.Log("MAIL - reverse path is too long: " + s.Envelope.MailFrom)
			s.pause(2)
			s.Out(550, "reverse path must be lower than 255 char (RFC 5321 4.5.1.3.1)")
			return
		}
		localDomain := strings.Split(s.Envelope.MailFrom, "@")
		if len(localDomain) == 1 {
			s.Log("MAIL - invalid address " + localDomain[0])
			s.pause(2)
			s.Out(501, "5.1.7 Invalid address")
			return
			/*
				localDomain = append(localDomain, Cfg.GetMe())
				s.Envelope.MailFrom = localDomain[0] + "@" + localDomain[1]
			*/
		}
		if Cfg.getRFCMailFromLocalpartSize() && len(localDomain[0]) > 64 {
			s.Log("MAIL - local part is too long: " + s.Envelope.MailFrom)
			s.pause(2)
			s.Out(550, "local part of reverse path MUST be lower than 65 char (RFC 5321 4.5.3.1.1)")
			return
		}
		if len(localDomain[1]) > 255 {
			s.Log("MAIL - domain part is too long: " + s.Envelope.MailFrom)
			s.pause(2)
			s.Out(550, "domain part of reverse path MUST be lower than 255 char (RFC 5321 4.5.3.1.2)")
			return
		}
		// domain part should be FQDN
		ok, err := isFQN(localDomain[1])
		if err != nil {
			s.LogError("MAIL - fail to do lookup on domain part. " + err.Error())
			s.Out(451, "unable to resolve "+localDomain[1]+" due to timeout or srv failure")
			return
		}
		if !ok {
			s.Log("MAIL - need fully-qualified hostname. " + localDomain[1] + " given")
			s.pause(2)
			s.Out(550, "5.5.2 need fully-qualified hostname for domain part")
			return
		}
	}
	// Plugin - hook "mailpost"
	done, drop := ExecSMTPdPlugins("mailpost", s)
	if done || drop {
		if drop {
			s.Log("plugin terminating session")
			s.ExitAsap()
			return
		}
		s.seenMail = true
		return
	}

	s.seenMail = true
	s.Log("MAIL FROM " + s.Envelope.MailFrom)
	s.Out(250, "OK")
}

// RCPT TO
func (s *SMTPServerSession) smtpRcptTo(msg []string) {
	defer s.recoverOnPanic()
	var err error

	// cmd EHLO ?
	if Cfg.getRFCHeloMandatory() && !s.seenHelo {
		s.pause(2)
		s.Out(503, "5.5.2 Send hello first")
		return
	}

	s.LastRcptTo = ""
	s.rcptCount++
	//s.LogDebug(fmt.Sprintf("RCPT TO %d/%d", s.rcptCount, Cfg.GetSmtpdMaxRcptTo()))
	if Cfg.GetSmtpdMaxRcptTo() != 0 && s.rcptCount > Cfg.GetSmtpdMaxRcptTo() {
		s.Log(fmt.Sprintf("max RCPT TO command reached (%d)", Cfg.GetSmtpdMaxRcptTo()))
		s.pause(2)
		s.Out(451, "4.5.3 max RCPT To commands reached for this sessions")
		return
	}
	// add pause if rcpt to > 10
	if s.rcptCount > 10 {
		s.pause(1)
	}
	if !s.seenMail {
		s.Log("RCPT before MAIL")
		s.pause(2)
		s.Out(503, "5.5.1 bad sequence")
		return
	}

	if len(msg) == 1 || !strings.HasPrefix(strings.ToLower(msg[1]), "to:") {
		s.Log(fmt.Sprintf("RCPT TO - Bad syntax : %s ", strings.Join(msg, " ")))
		s.pause(2)
		s.Out(501, "5.5.4 syntax: RCPT TO:<address>")
		return
	}

	// rcpt to: user
	if len(msg[1]) > 3 {
		t := strings.Split(msg[1], ":")
		s.LastRcptTo = strings.Join(t[1:], ":")
	} else if len(msg) > 2 {
		s.LastRcptTo = msg[2]
	}

	if len(s.LastRcptTo) == 0 {
		s.Log(fmt.Sprintf("RCPT - Bad syntax : %s ", strings.Join(msg, " ")))
		s.pause(2)
		s.Out(501, "5.5.4 syntax: RCPT TO:<address>")
		return
	}
	s.LastRcptTo = RemoveBrackets(s.LastRcptTo)

	// We MUST recognize source route syntax but SHOULD strip off source routing
	// RFC 5321 4.1.1.3
	t := strings.SplitAfter(s.LastRcptTo, ":")
	s.LastRcptTo = t[len(t)-1]

	// if no domain part and local part is postmaster FRC 5321 2.3.5
	if strings.ToLower(s.LastRcptTo) == "postmaster" {
		s.LastRcptTo += "@" + s.systemName
	}
	// Check validity
	_, err = mail.ParseAddress(s.LastRcptTo)
	if err != nil {
		s.Log(fmt.Sprintf("RCPT - bad email format : %s - %s ", strings.Join(msg, " "), err))
		s.pause(2)
		s.Out(501, "5.5.4 Bad email format")
		return
	}

	// rcpt accepted ?
	localDom := strings.Split(s.LastRcptTo, "@")
	if len(localDom) != 2 {
		s.Log(fmt.Sprintf("RCPT - Bad email format : %s ", strings.Join(msg, " ")))
		s.pause(2)
		s.Out(501, "5.5.4 Bad email format")
		return
	}

	// make domain part insensitive
	s.LastRcptTo = localDom[0] + "@" + strings.ToLower(localDom[1])

	// Relay granted for this recipient ?
	s.RelayGranted = false

	// Plugins
	done, drop := ExecSMTPdPlugins("rcptto", s)
	if done || drop {
		if drop {
			s.Log("plugin terminating session")
			s.ExitAsap()
			return
		}
		// s.Envelope.RcptTo needs to be set by plugin
		return
	}

	// check DB for rcpthost
	if !s.RelayGranted {
		rcpthost, err := RcpthostGet(localDom[1])
		if err != nil && err != gorm.ErrRecordNotFound {
			s.LogError("RCPT - relay access failed while queriyng for rcpthost. " + err.Error())
			s.pause(2)
			s.Out(455, "4.3.0 oops, problem with relay access")
			return
		}
		if err == nil {
			// rcpthost exists relay granted
			s.RelayGranted = true
			// if local check "mailbox" (destination)
			if rcpthost.IsLocal {
				s.LogDebug(rcpthost.Hostname + " is local")
				// check destination
				exists, err := IsValidLocalRcpt(strings.ToLower(s.LastRcptTo))
				if err != nil {
					s.LogError("RCPT - relay access failed while checking validity of local rpctto. " + err.Error())
					s.pause(2)
					s.Out(455, "4.3.0 oops, problem with relay access")
					return
				}
				if !exists {
					s.Log("RCPT - no mailbox here by that name: " + s.LastRcptTo)
					s.pause(2)
					s.Out(550, "5.5.1 Sorry, no mailbox here by that name")
					s.BadRcptToCount++
					if Cfg.GetSmtpdMaxBadRcptTo() != 0 && s.BadRcptToCount > Cfg.GetSmtpdMaxBadRcptTo() {
						s.Log("RCPT - too many bad rcpt to, connection droped")
						s.ExitAsap()
					}
					return
				}
			}
		}
	}
	// User authentified & access granted ?
	if !s.RelayGranted && s.user != nil {
		s.RelayGranted = s.user.AuthRelay
	}

	// Remote IP authorised ?
	if !s.RelayGranted {
		s.RelayGranted, err = IpCanRelay(s.Conn.RemoteAddr())
		if err != nil {
			s.LogError("RCPT - relay access failed while checking if IP is allowed to relay. " + err.Error())
			s.pause(2)
			s.Out(455, "4.3.0 oops, problem with relay access")
			return
		}
	}

	// Relay denied
	if !s.RelayGranted {
		s.Log("Relay access denied - from " + s.Envelope.MailFrom + " to " + s.LastRcptTo)
		s.pause(2)
		s.Out(554, "5.7.1 Relay access denied")
		return
	}

	// Check if there is already this recipient
	if !IsStringInSlice(s.LastRcptTo, s.Envelope.RcptTo) {
		s.Envelope.RcptTo = append(s.Envelope.RcptTo, s.LastRcptTo)
		s.Log("RCPT - + " + s.LastRcptTo)
	}
	s.Out(250, "250 OK")
}

// SMTPVrfy VRFY SMTP command
func (s *SMTPServerSession) smtpVrfy(msg []string) {
	defer s.recoverOnPanic()

	// cmd EHLO ?
	if Cfg.getRFCHeloMandatory() && !s.seenHelo {
		s.pause(2)
		s.Out(503, "5.5.2 Send hello first")
		return
	}

	rcptto := ""
	s.vrfyCount++
	s.LogDebug(fmt.Sprintf("VRFY -  %d/%d", s.vrfyCount, Cfg.GetSmtpdMaxVrfy()))
	if Cfg.GetSmtpdMaxVrfy() != 0 && s.vrfyCount > Cfg.GetSmtpdMaxVrfy() {
		s.Log(fmt.Sprintf(" VRFY - max command reached (%d)", Cfg.GetSmtpdMaxVrfy()))
		s.pause(2)
		s.Out(551, "5.5.3 too many VRFY commands for this sessions")
		return
	}
	// add pause if rcpt to > 10
	if s.vrfyCount > 10 {
		s.pause(1)
	} else if s.vrfyCount > 20 {
		s.pause(2)
	}

	if len(msg) != 2 {
		s.Log(fmt.Sprintf("VRFY - Bad syntax : %s", strings.Join(msg, " ")))
		s.pause(2)
		s.Out(551, "5.5.4 syntax: VRFY <address>")
		return
	}

	// vrfy: user
	rcptto = msg[1]
	if len(rcptto) == 0 {
		s.Log(fmt.Sprintf("VRFY - Bad syntax : %s", strings.Join(msg, " ")))
		s.pause(2)
		s.Out(551, "5.5.4 syntax: VRFY <address>")
		return
	}

	rcptto = RemoveBrackets(rcptto)

	// if no domain part and local part is postmaster FRC 5321 2.3.5
	if strings.ToLower(rcptto) == "postmaster" {
		rcptto += "@" + s.systemName
	}
	// Check validity
	_, err := mail.ParseAddress(rcptto)
	if err != nil {
		s.Log(fmt.Sprintf("VRFY - bad email format : %s - %s ", strings.Join(msg, " "), err))
		s.pause(2)
		s.Out(551, "5.5.4 Bad email format")
		return
	}

	// rcpt accepted ?
	localDom := strings.Split(rcptto, "@")
	if len(localDom) != 2 {
		s.Log("VRFY - Bad email format : " + rcptto)
		s.pause(2)
		s.Out(551, "5.5.4 Bad email format")
		return
	}
	// make domain part insensitive
	rcptto = localDom[0] + "@" + strings.ToLower(localDom[1])
	// check rcpthost

	rcpthost, err := RcpthostGet(localDom[1])
	if err != nil && err != gorm.ErrRecordNotFound {
		s.LogError("VRFY - relay access failed while queriyng for rcpthost. " + err.Error())
		s.Out(455, "4.3.0 oops, internal failure")
		return
	}
	if err == nil {
		// if local check "mailbox" (destination)
		if rcpthost.IsLocal {
			s.LogDebug("VRFY - " + rcpthost.Hostname + " is local")
			// check destination
			exists, err := IsValidLocalRcpt(strings.ToLower(rcptto))
			if err != nil {
				s.LogError("VRFY - relay access failed while checking validity of local rpctto. " + err.Error())
				s.Out(455, "4.3.0 oops, internal failure")
				return
			}
			if !exists {
				s.Log("VRFY - no mailbox here by that name: " + rcptto)
				s.pause(2)
				s.Out(551, "5.5.1 <"+rcptto+"> no mailbox here by that name")
				return
			}
			s.Out(250, "<"+rcptto+">")
			// relay
		} else {
			s.Out(252, "<"+rcptto+">")
		}
	} else {
		s.Log("VRFY - no mailbox here by that name: " + rcptto)
		s.pause(2)
		s.Out(551, "5.5.1 <"+rcptto+"> no mailbox here by that name")
		return
	}
}

// SMTPExpn EXPN SMTP command
func (s *SMTPServerSession) smtpExpn(_ []string) {
	s.Out(252, " ")
	return
}

// DATA
// plutot que de stocker en RAM on pourrait envoyer directement les danat
// dans un fichier ne queue
// Si il y a une erreur on supprime le fichier
// Voir un truc comme DATA -> temp file -> mv queue file
func (s *SMTPServerSession) smtpData(msg []string) {
	defer s.recoverOnPanic()
	if !s.seenMail || len(s.Envelope.RcptTo) == 0 {
		s.Log("DATA - out of sequence")
		s.pause(2)
		s.Out(503, "5.5.1 command out of sequence")
		return
	}

	if len(msg) > 1 {
		s.Log("DATA - invalid syntax: " + strings.Join(msg, " "))
		s.pause(2)
		s.Out(501, "5.5.4 invalid syntax")
		return
	}
	s.Out(354, "End data with <CR><LF>.<CR><LF>")

	// Get RAW mail
	s.CurrentRawMail = make([]byte, 0, 1024*1024)

	hops := 0       // nb of relay
	s.dataBytes = 0 // nb of bytes (size of message)

	// cache the config values for use in the loop
	maxHops := Cfg.GetSmtpdMaxHops()
	maxDataBytes := Cfg.GetSmtpdMaxDataBytes()

	headers := ""
	doneHeaders := false
	doneEmail := false
	var line []byte
	lines := uint64(0)

	sc := bufio.NewScanner(bufio.NewReader(s.Conn))
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, []byte{CR, LF}); i >= 0 {
			// We have a full newline-terminated line.
			return i + 2, data[0 : i+2], nil
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return len(data), data, nil
		}
		// If the line is too long.
		if len(data) > 1000 {
			return 0, nil, errors.New("SMTP line too long")
		}
		// Request more data.
		return 0, nil, nil
	}
	sc.Split(split)

	for {
		if !sc.Scan() {
			err := sc.Err()
			z := ""
			if err == nil {
				// scan ended, but if this a real EOF?
				// we check doneEmail later
				break
			} else {
				z = err.Error()
			}
			if z == "SMTP line too long" {
				s.LogError(fmt.Sprintf("DATA - %s", z))
				s.Out(500, fmt.Sprintf("%s", z))
				s.ExitAsap()
				return
			}
			// we will try to send an error message to client, but there is a LOT of
			// chance that is gone
			s.LogError(fmt.Sprintf("DATA - error receiving: %s", z))
			s.Out(454, "something wrong happened when reading data from you")
			s.ExitAsap()
			return
		}

		line = sc.Bytes()

		if bytes.Equal(line, []byte{0x2E, CR, LF}) {
			doneEmail = true
			break
		}

		if !doneHeaders {
			// count hops in headers
			sLine := strings.ToLower(string(line))
			if strings.HasPrefix(sLine, "received: ") || strings.HasPrefix(sLine, "delivered: ") {
				hops++
			}

			headers = headers + sLine
			if len(headers) > MAXTOTALHEADERSIZE {
				s.Log(fmt.Sprintf("DATA - Headers in the message are too long: %d", len(headers)))
				s.Out(500, "headers in this message are too long")
				// No point to leave the session open, some clients don't check the server response
				// until they finish sending the whole email body.
				s.ExitAsap()
				return
			}
			if bytes.Equal(line, []byte{CR, LF}) {
				doneHeaders = true

				// Max hops reached ?
				if hops > maxHops {
					s.Log(fmt.Sprintf("DATA - Message is looping. Hops : %d", hops))
					s.Out(554, "5.4.6 too many hops, this message is looping")
					// No point to leave the session open, some clients don't check the server response
					// until they finish sending the whole email body.
					s.ExitAsap()
					return
				}
			}
		}
		s.dataBytes = s.dataBytes + uint64(len(line))

		// Max databytes reached ?
		if s.dataBytes > maxDataBytes {
			s.Log(fmt.Sprintf("DATA - Message size (%d) exceeds maxDataBytes (%d).", s.dataBytes, maxDataBytes))
			s.Out(552, "5.3.4 sorry, that message size exceeds my databytes limit")
			// No point to leave the session open, some clients don't check the server response
			// until they finish sending the whole email body.
			s.ExitAsap()
			return
		}
		// TODO: optimize more by reading directly into slice?
		s.CurrentRawMail = append(s.CurrentRawMail, line...)

		lines++
		if lines%1000 == 0 {
			s.resetTimeout()
		}
	}

	// If no headers in the message, treat the data as the message body only
	// and add a leading CRLF before the body as we're adding our own headers to the message below.
	if !doneHeaders {
		headers = ""
		s.CurrentRawMail = append([]byte{CR, LF}, s.CurrentRawMail...)
	}

	s.Log(fmt.Sprintf("DATA - received %d bytes", s.dataBytes))
	if !doneEmail {
		s.LogError("DATA - unable to read a complete email message")
		s.Out(454, "something wrong happened when reading data from you")
		s.ExitAsap()
		return
	}

	// scan
	// clamav
	if Cfg.GetSmtpdClamavEnabled() {
		found, virusName, err := NewClamav().ScanStream(bytes.NewReader(s.CurrentRawMail))
		Logger.Debug("clamav scan result", found, virusName, err)
		if err != nil {
			s.LogError("MAIL - clamav: " + err.Error())
			s.Out(454, "4.3.0 scanner failure")
			//s.purgeConn()
			s.Reset()
			return
		}
		if found {
			s.pause(2)
			s.Out(554, "5.7.1 message infected by "+virusName)
			s.Log("MAIL - infected by " + virusName)
			//s.purgeConn()
			s.Reset()
			return
		}
	}

	// Message-ID
	HeaderMessageID := message.RawGetMessageId(&s.CurrentRawMail)
	if len(HeaderMessageID) == 0 {
		atDomain := s.systemName
		if strings.Count(s.Envelope.MailFrom, "@") != 0 {
			atDomain = strings.ToLower(strings.Split(s.Envelope.MailFrom, "@")[1])
		}
		HeaderMessageID = []byte(fmt.Sprintf("%d.%s@%s", time.Now().Unix(), s.uuid, atDomain))
		s.CurrentRawMail = append([]byte(fmt.Sprintf("Message-ID: <%s>\r\n", HeaderMessageID)), s.CurrentRawMail...)

	}
	s.Log("message-id:", string(HeaderMessageID))

	authUser := ""
	if s.user != nil {
		authUser = s.user.Login
	}

	// Add received header
	remoteIP, _, err := net.SplitHostPort(s.Conn.RemoteAddr().String())
	if err != nil {
		remoteIP = "unknown"
	}
	remoteHost := "unknown"
	remoteHosts, err := net.LookupAddr(remoteIP)
	if err == nil {
		remoteHost = strings.TrimSuffix(remoteHosts[0], ".")
	}

	// why resolve local host?
	/*
		localIP, _, err := net.SplitHostPort(s.Conn.LocalAddr().String())
		if err != nil {
			localIP = "unknown"
		}
		localHost := "unknown"
		localHosts, err := net.LookupAddr(localIP)
		if err == nil {
			localHost = localHosts[0]
		}
	*/

	received := "Received: from "
	if authUser != "" && Cfg.GetSmtpdHideReceivedFromAuth() {
		received += message.AuthDataStart
	}
	received += fmt.Sprintf("%s ([%s] ", remoteHost, remoteIP)
	// helo
	received += fmt.Sprintf("helo=[%s])", s.helo)
	if authUser != "" && Cfg.GetSmtpdHideReceivedFromAuth() {
		received += message.AuthDataEnd
	}
	received += "\r\n"

	// local
	// only hostname is enough?
	//received += fmt.Sprintf("        by %s ([%s]) ", localHost, localIP)
	received += fmt.Sprintf("        by %s ", s.systemName)

	// Proto
	if s.tls {
		received += "with ESMTPS (" + tlsGetVersion(s.connTLS.ConnectionState().Version) +
			" " + tlsGetCipherSuite(s.connTLS.ConnectionState().CipherSuite) + ")"
	} else {
		received += "with SMTP"
	}
	received += "\r\n"

	// cocosmail version
	received += "        (cocosmail " + Version + ")" + "\r\n"

	// envelope from
	received += "        (envelope-from " + s.Envelope.MailFrom + ")" + "\r\n"

	// uuid
	received += "        id " + s.uuid + "\r\n"
	// envelope for and timestamp
	received += "        for " + s.Envelope.RcptTo[0] + "; " + Format822Date() + "\r\n"

	s.CurrentRawMail = append([]byte(received), s.CurrentRawMail...)
	received = ""

	// X-Env-from
	s.CurrentRawMail = append([]byte("X-Env-From: "+s.Envelope.MailFrom+"\r\n"), s.CurrentRawMail...)

	// Plugins
	_, drop := ExecSMTPdPlugins("data", s)
	if drop {
		s.ExitAsap()
		return
	}

	// Plugins
	done, drop := ExecSMTPdPlugins("beforequeue", s)
	if done || drop {
		if drop {
			s.ExitAsap()
			return
		}
		// A plugin can call QueueAddMessage if it processes it.
		// It also needs to send its own response using s.Out().
		s.Reset()
		return
	}

	// put message in queue
	id, err := QueueAddMessage(&s.CurrentRawMail, s.Envelope, authUser)
	if err != nil {
		s.LogError("MAIL - unable to put message in queue -", err.Error())
		s.Out(451, "temporary queue error")
		s.Reset()
		return
	}
	s.Log("message queued as", id)
	s.Out(250, fmt.Sprintf("2.0.0 OK: message queued %s", id))
	s.Reset()
	return
}

// QUIT
func (s *SMTPServerSession) smtpQuit() {
	// Plugins
	ExecSMTPdPlugins("quit", s)

	s.Out(221, fmt.Sprintf("2.0.0 Bye"))
	s.ExitAsap()
}

// Starttls
func (s *SMTPServerSession) smtpStartTLS() {
	if s.tls {
		s.Out(454, "transaction is already over SSL/TLS")
		return
	}

	// cmd EHLO ?
	if Cfg.getRFCHeloMandatory() && !s.seenHelo {
		s.pause(2)
		s.Out(503, "5.5.2 Send hello first")
		return
	}

	cert, err := tls.LoadX509KeyPair(
		path.Join(Cfg.GetBasePath(), fmt.Sprintf("ssl/smtp-%s.crt", s.certName)),
		path.Join(Cfg.GetBasePath(), fmt.Sprintf("ssl/smtp-%s.key", s.certName)))
	if err != nil {
		errmsg := "TLS failed unable to load server keys"
		s.LogError(fmt.Sprintf("%s: %s", errmsg, err.Error()))
		s.Out(454, errmsg)
		return
	}

	tlsConfig := tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	tlsConfig.Rand = rand.Reader

	s.Out(220, "Ready to start TLS nego")

	s.connTLS = tls.Server(s.Conn, &tlsConfig)
	// run a handshake
	// errors.New("tls: unsupported SSLv2 handshake received")
	err = s.connTLS.Handshake()
	if err != nil {
		errmsg := "TLS handshake failed: " + err.Error()
		if err.Error() == "tls: unsupported SSLv2 handshake received" {
			s.Log(errmsg)
		} else {
			s.LogError(errmsg)
		}
		s.Out(454, "TLS handshake failed")
		return
	}
	s.Log(
		"connection upgraded to " + tlsGetVersion(s.connTLS.ConnectionState().Version) +
			" " + tlsGetCipherSuite(s.connTLS.ConnectionState().CipherSuite),
	)
	s.Conn = s.connTLS
	s.tls = true
	s.seenHelo = false
}

// Read one line of SMTP command or text.
// Uses 1-byte read from socket.
func (s *SMTPServerSession) readLine() (line string, err error) {
	ch := make([]byte, 1)
	for {
		s.resetTimeout()
		_, err := s.Conn.Read(ch)
		if err != nil {
			if err.Error() == "EOF" {
				s.LogDebug(s.Conn.RemoteAddr().String(), "- Client sent EOF")
			} else if strings.Contains(err.Error(), "connection reset by peer") {
				s.Log(err.Error())
			} else if !strings.Contains(err.Error(), "use of closed network connection") {
				s.LogError("unable to read data from client - ", err.Error())
			}
			s.ExitAsap()
			return "", err
		}
		if ch[0] == LF {
			s.timer.Stop()
			break
		}
		line = line + string(ch[0])
		// SMTP command or line length must not be longer than 512 bytes, according to RFC 821
		if len(line) > 512 {
			errmsg := "SMTP line too long"
			s.LogError(fmt.Sprintf("%s: %s", errmsg, line))
			s.Out(500, fmt.Sprintf("%s", errmsg))
			return line, errors.New("SMTP line too long")
		}
	}
	if !strings.HasSuffix(line, "\r") {
		errmsg := "SMTP line malformed, not ending with <CR><LF>"
		s.LogError(fmt.Sprintf("%s: %s", errmsg, line))
		s.Out(500, fmt.Sprintf("%s", errmsg))
		return line, errors.New("SMTP line malformed")
	}
	return line[:len(line)-1], err
}

// Read one line of SMTP command or text.
// Uses a scanner.
func (s *SMTPServerSession) readLine2() (line string, err error) {
	sc := bufio.NewScanner(bufio.NewReader(s.Conn))
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, []byte{CR, LF}); i >= 0 {
			// We have a full newline-terminated line.
			return i + 2, data[0 : i+2], nil
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return 0, nil, errors.New("SMTP line not terminated")
		}
		// If the line is too long.
		if len(data) > 512 {
			return 0, nil, errors.New("SMTP line too long")
		}
		// Request more data.
		return 0, nil, nil
	}
	sc.Split(split)

	if !sc.Scan() {
		err := sc.Err()
		if err != nil {
			if err.Error() == "EOF" {
				s.LogDebug(s.Conn.RemoteAddr().String(), "- Client sent EOF")
			} else if strings.Contains(err.Error(), "connection reset by peer") {
				s.Log(err.Error())
			} else if !strings.Contains(err.Error(), "use of closed network connection") {
				s.LogError("unable to read data from client - ", err.Error())
			}
			s.ExitAsap()
			return "", err
			/*
				s.LogError(fmt.Sprintf("error receiving line: %s", err.Error()))
				s.Out(500, err.Error())
				return line, err
			*/
		}
		s.LogDebug("- Client sent EOF")
		s.ExitAsap()
		return "", errors.New("client sent EOF")
	}

	line = string(sc.Bytes())

	if !strings.HasSuffix(line, "\r\n") {
		errmsg := "SMTP line malformed, not ending with <CR><LF>"
		s.LogError(fmt.Sprintf("%s: %s", errmsg, line))
		s.Out(500, fmt.Sprintf("%s", errmsg))
		return line, errors.New("SMTP line malformed")
	}

	return line[:len(line)-2], err
}

// SMTP AUTH
func (s *SMTPServerSession) smtpAuth(rawMsg string) {
	defer s.recoverOnPanic()

	// seen HELO?
	if Cfg.getRFCHeloMandatory() && !s.seenHelo {
		s.pause(2)
		s.Out(503, "5.5.2 Send hello first")
		return
	}

	// Disable AUTH for non-secure connection
	if !s.tls {
		s.pause(2)
		s.Out(530, "5.7.0 Must issue a STARTTLS command first")
		s.Log(fmt.Sprintf("AUTH attempt via plain connection: %s", rawMsg))
		return
	}

	splitted := strings.Split(rawMsg, " ")

	if len(splitted) < 2 {
		s.Out(555, "5.5.2 Syntax error")
		s.Log(fmt.Sprintf("AUTH syntax error: %s", rawMsg))
		return
	}

	var err error
	authLogin, authPasswd, encoded := "", "", ""
	authType := strings.ToUpper(splitted[1])

	switch authType {
	case "PLAIN":
		// AUTH PLAIN xxxxxxxxxxxx
		switch len(splitted) {
		case 3:
			encoded = splitted[2]
			// AUTH PLAIN
		case 2:
			s.Out(334, "")
			// get encoded by reading next line
			encoded, err = s.readLine2()
			if err != nil {
				return
			}
			s.LogDebug("<", encoded)
		default:
			s.pause(2)
			s.Out(501, "5.5.4 malformed auth input")
			s.Log("malformed auth input: " + rawMsg)
			return
		}
		// decode  "authorize-id\0userid\0passwd\0"
		authData, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			s.pause(2)
			s.Out(501, "5.5.4 malformed auth input")
			s.Log("malformed auth input: " + rawMsg + " err:" + err.Error())
			return
		}

		// split
		t := make([][]byte, 3)
		i := 0
		for _, b := range authData {
			if b == 0 {
				i++
				continue
			}
			t[i] = append(t[i], b)
		}
		authLogin = string(t[1])
		authPasswd = string(t[2])

	case "LOGIN":
		// prompt for "Username:"
		s.Out(334, "VXNlcm5hbWU6")
		// get encoded login by reading the next line
		encoded, err = s.readLine2()
		if err != nil {
			return
		}
		s.LogDebug("<", encoded)

		var decoded []byte
		// decode Username
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			s.pause(2)
			s.Out(501, "5.5.4 malformed auth input")
			s.Log(fmt.Sprintf("malformed auth input: %s err: %s", encoded, err.Error()))
			return
		}
		authLogin = string(decoded)

		// prompt for "Password:"
		s.Out(334, "UGFzc3dvcmQ6")
		// get encoded password by reading the next line
		encoded, err = s.readLine2()
		if err != nil {
			return
		}
		s.LogDebug("<", encoded)
		// decode Username
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			s.pause(2)
			s.Out(501, "5.5.4 malformed auth input")
			s.Log(fmt.Sprintf("malformed auth input: %s err: %s", encoded, err.Error()))
			return
		}
		authPasswd = string(decoded)

	/*
		case "CRAM-MD5":
			// create a challenge
			nBig, err := rand.Int(rand.Reader, big.NewInt(27))
			if err != nil {
				s.pause(2)
				s.Out(454, "4.3.0 oops, problem with auth")
				s.Log(fmt.Sprintf("ERROR rand.Int(): %s", err.Error()))
				return
			}
			challenge := fmt.Sprintf("<%d.%d@%s>", nBig.Int64(), time.Now().Unix(), s.systemName)

			// send the base64 encoded challenge
			s.Out(334, fmt.Sprintf("%s", base64.StdEncoding.EncodeToString([]byte(challenge))))
			// get the response
			encoded, err = s.readLine2()
			if err != nil {
				return
			}
			s.LogDebug("<", encoded)

			var decoded []byte
			// base64decode CRAM-MD5 response
			decoded, err = base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				s.pause(2)
				s.Out(501, "5.5.4 malformed auth input")
				s.Log(fmt.Sprintf("malformed auth input: %s err: %s", encoded, err.Error()))
				return
			}
			response := strings.Split(string(decoded), " ")
			if len(response) != 2 {
				s.pause(2)
				s.Out(501, "5.5.4 malformed auth input")
				s.Log(fmt.Sprintf("malformed auth input: %s", string(decoded)))
				return
			}

			authLogin = response[0]
			user, err := UserGetByLogin(authLogin)
			if err != nil {
				break
			}
			// TODO: keep ipad and opad of the password in the db to make CRAM-MD5 possible
			user.Passwd = "123456"
			h := hmac.New(md5.New, []byte(user.Passwd))
			h.Write([]byte(challenge))
			digest := hex.EncodeToString(h.Sum(nil))

			// compare digests
			if digest != response[1] {
				s.pause(2)
				s.Out(535, "5.7.1 authentication failed")
				AuthSMTPdPlugins(authLogin, authPasswd, false, s)
				s.Log(fmt.Sprintf("CRAM-MD5 auth failed, response: %s, required: %s", response[1], digest))
				s.ExitAsap()
				return
			}

			// set the correct password
			authPasswd = user.Passwd
	*/
	default:
		s.pause(2)
		s.Out(504, "5.7.4 unrecognized authentication type")
		s.Log(fmt.Sprintf("unrecognized authentication type: %s", authType))
		//s.ExitAsap()
		return
	}

	s.user, err = UserGet(authLogin, authPasswd)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.pause(2)
			s.Out(535, "5.7.1 authentication failed")
			AuthSMTPdPlugins(authLogin, authPasswd, false, s)
			s.Log("auth failed, no such user: " + rawMsg + " err:" + err.Error())
			s.ExitAsap()
			return
		}
		if err == bcrypt.ErrMismatchedHashAndPassword {
			s.pause(2)
			s.Out(535, "5.7.1 authentication failed")
			AuthSMTPdPlugins(authLogin, authPasswd, false, s)
			s.Log("auth failed: " + rawMsg + " err:" + err.Error())
			s.ExitAsap()
			return
		}
		s.pause(2)
		s.Out(454, "4.3.0 oops, problem with auth")
		AuthSMTPdPlugins(authLogin, authPasswd, false, s)
		s.Log("ERROR auth " + rawMsg + " err:" + err.Error())
		s.ExitAsap()
		return
	}
	s.Log("auth succeed for user " + s.user.Login)
	s.Out(235, "2.0.0 ok, go ahead")
	AuthSMTPdPlugins(authLogin, authPasswd, true, s)
}

// RSET SMTP ahandler
func (s *SMTPServerSession) rset() {
	s.Reset()
	s.Out(250, "2.0.0 OK")
}

// NOOP SMTP handler
func (s *SMTPServerSession) noop() {
	s.Out(250, "2.0.0 OK")
	s.resetTimeout()
}

// Handle SMTP session
func (s *SMTPServerSession) handle() {
	defer s.recoverOnPanic()

	// initialize all active smtpd plugins
	InitSMTPdPlugins(s)

	// welcome (
	s.smtpGreeting()

	for {
		smtpLine, err := s.readLine2()
		if err != nil {
			break
		}
		s.lastClientCmd = []byte(smtpLine)
		s.LogDebug("< " + smtpLine)
		//smtpLine = strings.TrimSpace(smtpLine)

		var smtpArgs []string
		for _, m := range strings.Split(smtpLine, " ") {
			m = strings.TrimSpace(m)
			if m != "" {
				smtpArgs = append(smtpArgs, m)
			}
		}

		// get command, first word
		// TODO: Use textproto / scanner
		if len(smtpArgs) != 0 {
			verb := strings.ToLower(smtpArgs[0])
			switch verb {
			case "helo":
				s.smtpHelo(smtpArgs)
			case "ehlo":
				s.smtpEhlo(smtpArgs)
			case "mail":
				s.smtpMailFrom(smtpArgs)
			case "vrfy":
				s.smtpVrfy(smtpArgs)
			case "expn":
				s.smtpExpn(smtpArgs)
			case "rcpt":
				s.smtpRcptTo(smtpArgs)
			case "data":
				s.smtpData(smtpArgs)
			case "starttls":
				s.smtpStartTLS()
			case "auth":
				s.smtpAuth(smtpLine)
			case "rset":
				s.rset()
			case "noop":
				s.noop()
			case "quit":
				s.smtpQuit()
			default:
				s.Log("unimplemented command from client:", smtpLine)
				s.Out(502, "5.5.1 unimplemented")
			}
			if NotifySMTPdPlugins(s) {
				s.Log("plugin terminating session")
				s.ExitAsap()
			}
		}
		//s.resetTimeout()
		s.lastClientCmd = []byte{}
	}
	s.Log("EOT")
	return
}
