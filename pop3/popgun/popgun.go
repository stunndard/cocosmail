/*
- implementation of POP3 server according to rfc1939, rfc2449 in progress
*/

package popgun

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	STATE_AUTHORIZATION = iota + 1
	STATE_TRANSACTION
	STATE_UPDATE
)

const (
	LOG_INFO = iota + 1
	LOG_DEBUG
	LOG_ERROR
)

type Config struct {
	ListenInterface string
	UseTls          bool
	TlsConfig       *tls.Config
	ServerName      string
}

type Authorizator interface {
	Authorize(user, pass string) bool
}

type Backend interface {
	Stat(user string) (messages, octets int, err error)
	List(user string) (octets []int, err error)
	ListMessage(user string, msgId int) (exists bool, octets int, err error)
	Retr(user string, msgId int) (message string, err error)
	Dele(user string, msgId int) error
	Rset(user string) error
	Uidl(user string) (uids []string, err error)
	UidlMessage(user string, msgId int) (exists bool, uid string, err error)
	Update(user string) error
	Lock(user string) (inUse bool, err error)
	Unlock(user string) error
	TopMessage(user string, msgId, msgLines int) (exists bool, message string, err error)
	Log(s string, loglevel int)
}

var (
	ErrInvalidState = fmt.Errorf("Invalid state")
)

//---------------CLIENT

type Client struct {
	commands     map[string]Executable
	printer      *Printer
	isAlive      bool
	currentState int
	authorizator Authorizator
	backend      Backend
	user         string
	pass         string
	lastCommand  string
	serverName   string
	// id and remote address of the session, in every log line
	id     string
	remote string
}

// logf logs a message of the session, like smtpd: ID-REMOTE-message
func (c *Client) logf(level int, format string, a ...interface{}) {
	c.backend.Log(fmt.Sprintf("%s-%s-%s", c.id, c.remote, fmt.Sprintf(format, a...)), level)
}

// newSessionID returns a random session id, like smtpd ones
func newSessionID() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newClient(authorizator Authorizator, backend Backend, serverName string) *Client {
	commands := make(map[string]Executable)

	commands["QUIT"] = QuitCommand{}
	commands["USER"] = UserCommand{}
	commands["PASS"] = PassCommand{}
	commands["STAT"] = StatCommand{}
	commands["LIST"] = ListCommand{}
	commands["RETR"] = RetrCommand{}
	commands["DELE"] = DeleCommand{}
	commands["NOOP"] = NoopCommand{}
	commands["RSET"] = RsetCommand{}
	commands["UIDL"] = UidlCommand{}
	commands["CAPA"] = CapaCommand{}
	commands["TOP"] = TopCommand{}

	return &Client{
		commands:     commands,
		currentState: STATE_AUTHORIZATION,
		authorizator: authorizator,
		backend:      backend,
		serverName:   serverName,
	}
}

func (c Client) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
	c.id = newSessionID()
	c.remote = conn.RemoteAddr().String()
	c.printer = NewPrinter(conn)
	c.printer.log = func(line string) { c.logf(LOG_DEBUG, "> %s", line) }
	c.logf(LOG_INFO, "starting new session")
	defer c.logf(LOG_INFO, "EOT")

	c.isAlive = true
	reader := bufio.NewReader(conn)

	c.printer.Welcome(fmt.Sprintf("+OK %s POP3 server ready\r\n", c.serverName))

	for c.isAlive {
		// according to RFC commands are terminated by CRLF, but we are removing \r in parseInput
		if c.currentState == STATE_TRANSACTION {
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				c.logf(LOG_DEBUG, "connection closed by client")
			} else {
				c.logf(LOG_INFO, "error reading input: %s", err)
			}
			if c.currentState == STATE_TRANSACTION {
				c.logf(LOG_DEBUG, "unlocking user %s due to connection error", c.user)
				c.backend.Unlock(c.user)
			}
			break
		}

		cmd, args := c.parseInput(input)
		if cmd == "PASS" {
			c.logf(LOG_DEBUG, "< PASS ********")
		} else {
			c.logf(LOG_DEBUG, "< %s", strings.TrimRight(input, "\r\n"))
		}
		exec, ok := c.commands[cmd]
		if !ok {
			c.printer.Err("Invalid command %s", cmd)
			continue
		}
		state, err := exec.Run(&c, args)
		if err != nil {
			c.logf(LOG_INFO, "%s failed: %v", cmd, err)
			continue
		}
		c.lastCommand = cmd
		c.currentState = state
	}
}

func (c Client) parseInput(input string) (string, []string) {
	input = strings.Trim(input, "\r \n")
	cmd := strings.Split(input, " ")
	return strings.ToUpper(cmd[0]), cmd[1:]
}

//---------------SERVER

type Server struct {
	listener net.Listener
	config   Config
	auth     Authorizator
	backend  Backend
	// clients being served
	clients sync.WaitGroup
}

func NewServer(cfg *Config, auth Authorizator, backend Backend) *Server {
	return &Server{
		config:  *cfg,
		auth:    auth,
		backend: backend,
	}
}

func (s *Server) Start() error {
	var err error
	if s.config.UseTls {
		s.listener, err = tls.Listen("tcp", s.config.ListenInterface, s.config.TlsConfig)
		if err != nil {
			s.backend.Log(fmt.Sprintf("Error: could not listen on %s", s.config.ListenInterface), LOG_DEBUG)
			return err
		}
	} else {
		s.listener, err = net.Listen("tcp", s.config.ListenInterface)
		if err != nil {
			s.backend.Log(fmt.Sprintf("Error: could not listen on %s", s.config.ListenInterface), LOG_DEBUG)
			return err
		}
	}
	go func() {
		s.backend.Log(fmt.Sprintf("Server listening on: %s", s.config.ListenInterface), LOG_DEBUG)
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				// closed by Close
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.backend.Log(fmt.Sprintf("Error: could not accept connection: %s", err), LOG_INFO)
				continue
			}

			c := newClient(s.auth, s.backend, s.config.ServerName)
			s.clients.Add(1)
			go func() {
				defer s.clients.Done()
				c.handle(conn)
			}()
		}
	}()

	return nil
}

// Close stops accepting connections, clients being served go on
func (s *Server) Close() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

// Wait waits up to timeout for clients being served.
// It returns false if some are still connected.
func (s *Server) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.clients.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

//---------------PRINTER

type Printer struct {
	conn net.Conn
	// log is called with every line sent, if set
	log func(line string)
}

func (p Printer) logLine(line string) {
	if p.log != nil {
		p.log(line)
	}
}

func NewPrinter(conn net.Conn) *Printer {
	return &Printer{conn: conn}
}

func (p Printer) Welcome(s string) {
	fmt.Fprint(p.conn, s)
	p.logLine(strings.TrimRight(s, "\r\n"))
}

func (p Printer) Ok(msg string, a ...interface{}) {
	line := fmt.Sprintf("+OK %s", fmt.Sprintf(msg, a...))
	fmt.Fprintf(p.conn, "%s\r\n", line)
	p.logLine(line)
}

func (p Printer) Err(msg string, a ...interface{}) {
	line := fmt.Sprintf("-ERR %s", fmt.Sprintf(msg, a...))
	fmt.Fprintf(p.conn, "%s\r\n", line)
	p.logLine(line)
}

// MultiLine sends lines, and logs them
func (p Printer) MultiLine(msgs []string) {
	for _, line := range msgs {
		p.logLine(strings.Trim(line, "\r"))
	}
	p.logLine(".")
	p.sendLines(msgs)
}

// Message sends a message, only its size is logged
func (p Printer) Message(msgs []string) {
	p.logLine(fmt.Sprintf("(message, %d lines)", len(msgs)))
	p.logLine(".")
	p.sendLines(msgs)
}

func (p Printer) sendLines(msgs []string) {
	for _, line := range msgs {
		line := strings.Trim(line, "\r")
		if strings.HasPrefix(line, ".") {
			fmt.Fprintf(p.conn, ".%s\r\n", line)
		} else {
			fmt.Fprintf(p.conn, "%s\r\n", line)
		}
	}
	fmt.Fprint(p.conn, ".\r\n")
}
