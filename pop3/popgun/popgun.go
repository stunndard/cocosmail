/*
- implementation of POP3 server according to rfc1939, rfc2449 in progress
*/

package popgun

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
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
	c.printer = NewPrinter(conn)

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
				c.backend.Log("Connection closed by client", LOG_DEBUG)
			} else {
				c.backend.Log(fmt.Sprintf("Error reading input: %s", err), LOG_DEBUG)
			}
			if c.currentState == STATE_TRANSACTION {
				c.backend.Log(fmt.Sprintf("Unlocking user %s due to connection error", c.user), LOG_DEBUG)
				c.backend.Unlock(c.user)
			}
			break
		}

		cmd, args := c.parseInput(input)
		exec, ok := c.commands[cmd]
		if !ok {
			c.printer.Err("Invalid command %s", cmd)
			c.backend.Log(fmt.Sprintf("Invalid command: %s", cmd), LOG_DEBUG)
			continue
		}
		state, err := exec.Run(&c, args)
		if err != nil {
			//c.printer.Err("Error executing command %s", cmd)
			c.backend.Log(fmt.Sprintf("Error executing command %s: %s %v", cmd, args, err), LOG_DEBUG)
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
				s.backend.Log(fmt.Sprintf("Error: could not accept connection: %s", err), LOG_INFO)
				continue
			}

			c := newClient(s.auth, s.backend, s.config.ServerName)
			go c.handle(conn)
		}
	}()

	return nil
}

//---------------PRINTER

type Printer struct {
	conn net.Conn
}

func NewPrinter(conn net.Conn) *Printer {
	return &Printer{conn}
}

func (p Printer) Welcome(s string) {
	fmt.Fprintf(p.conn, s)
}

func (p Printer) Ok(msg string, a ...interface{}) {
	fmt.Fprintf(p.conn, "+OK %s\r\n", fmt.Sprintf(msg, a...))
}

func (p Printer) Err(msg string, a ...interface{}) {
	fmt.Fprintf(p.conn, "-ERR %s\r\n", fmt.Sprintf(msg, a...))
}

func (p Printer) MultiLine(msgs []string) {
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
