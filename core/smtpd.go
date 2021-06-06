package core

import (
	"crypto/tls"
	"log"
	"net"
	"path"
)

// Smtpd SMTP Server
type Smtpd struct {
	dsn Dsn
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
		cert, err := tls.LoadX509KeyPair(path.Join(Cfg.GetBasePath(), "ssl/server.crt"), path.Join(Cfg.GetBasePath(), "ssl/server.key"))
		if err != nil {
			log.Fatalln("unable to load SSL keys for smtpd.", "dsn:", s.dsn.TcpAddr, "ssl", s.dsn.Ssl, "err:", err)
		}
		// TODO: http://fastah.blackbuck.mobi/blog/securing-https-in-go/
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}
		listener, err = tls.Listen(s.dsn.TcpAddr.Network(), s.dsn.TcpAddr.String(), tlsConfig)
		if err != nil {
			log.Fatalln("unable to create TLS listener.", err)
		}
	} else {
		listener, err = net.Listen(s.dsn.TcpAddr.Network(), s.dsn.TcpAddr.String())
		if err != nil {
			log.Fatalln("unable to create listener")
		}
	}
	if err != nil {
		log.Fatalln(err)
	} else {
		defer listener.Close()
		for {
			conn, error := listener.Accept()
			if error != nil {
				log.Println("Client error: ", error)
			} else {
				go func(conn net.Conn) {
					ChSmtpSessionsCount <- 1
					defer func() { ChSmtpSessionsCount <- -1 }()
					sss, err := NewSMTPServerSession(conn, s.dsn.Ssl)
					if err != nil {
						log.Println("unable to get new SmtpServerSession.", err)
					} else {
						sss.handle()
					}
				}(conn)
			}
		}
	}
}
