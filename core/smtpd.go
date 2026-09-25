package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"path"
	"sync"
	"sync/atomic"
)

// Smtpd SMTP Server
type Smtpd struct {
	dsn Dsn
}

var (
	smtpdListeners   []net.Listener
	smtpdListenersMu sync.Mutex
)

// CloseSmtpdListeners stops accepting new SMTP connections, sessions go on
func CloseSmtpdListeners() {
	smtpdListenersMu.Lock()
	defer smtpdListenersMu.Unlock()
	for _, l := range smtpdListeners {
		_ = l.Close()
	}
	smtpdListeners = nil
}

// NewSmtpd returns a new SmtpServer
func NewSmtpd(d Dsn) *Smtpd {
	return &Smtpd{d}
}

// ListenAndServe launch server
func (s *Smtpd) ListenAndServe() {
	var listener net.Listener
	var err error
	var tlsConfig *tls.Config
	// SSL ?
	if s.dsn.Ssl {
		cert, err := tls.LoadX509KeyPair(
			path.Join(Cfg.GetBasePath(), fmt.Sprintf("ssl/smtp-%s.crt", s.dsn.CertName)),
			path.Join(Cfg.GetBasePath(), fmt.Sprintf("ssl/smtp-%s.key", s.dsn.CertName,
			)))
		if err != nil {
			log.Fatalln("unable to load SSL keys for smtpd.", "dsn:", s.dsn.TcpAddr, "ssl", s.dsn.Ssl, "err:", err)
		}
		// TODO: http://fastah.blackbuck.mobi/blog/securing-https-in-go/
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS12,
		}
		listener, err = tls.Listen(s.dsn.TcpAddr.Network(), s.dsn.TcpAddr.String(), tlsConfig)
		if err != nil {
			log.Fatalln("unable to create TLS listener.", err)
		}
	} else {
		listener, err = net.Listen(s.dsn.TcpAddr.Network(), s.dsn.TcpAddr.String())
		if err != nil {
			log.Fatalln("unable to create listener.", err)
		}
	}

	defer func() { _ = listener.Close() }()
	smtpdListenersMu.Lock()
	smtpdListeners = append(smtpdListeners, listener)
	smtpdListenersMu.Unlock()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// closed by CloseSmtpdListeners
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Println("Client error: ", err)
			continue
		}

		go func(conn net.Conn) {
			sess, err := NewSMTPServerSession(conn, s.dsn)
			if err != nil {
				log.Println("unable to get new SmtpServerSession.", err)
				return
			}
			atomic.AddInt32(&SmtpSessionsCount, 1)
			sess.handle()
			atomic.AddInt32(&SmtpSessionsCount, -1)
		}(conn)
	}
}
