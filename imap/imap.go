// Package imap is the IMAP server: users read their mail in folders, kept in
// Maildirs by mailstore, which the POP3 server and local delivery share.
package imap

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/cocosmail/imap/goimap"
	"github.com/stunndard/cocosmail/imap/goimap/imapserver"
	"github.com/stunndard/cocosmail/mailstore"
	"golang.org/x/crypto/bcrypt"
)

// capabilities beyond IMAP4rev1, all handled by mailstore
var caps = imap.CapSet{
	imap.CapIMAP4rev1:    {},
	imap.CapIMAP4rev2:    {},
	imap.CapNamespace:    {},
	imap.CapUIDPlus:      {},
	imap.CapESearch:      {},
	imap.CapSearchRes:    {},
	imap.CapListExtended: {},
	imap.CapListStatus:   {},
	imap.CapMove:         {},
	imap.CapStatusSize:   {},
	imap.CapBinary:       {},
	imap.CapChildren:     {},
	imap.CapSpecialUse:   {},
}

// session is an IMAP connection
type session struct {
	// id and remote address, in every log line like smtpd and pop3d
	id, remote string
	user       string
	boxes      mailstore.Mailboxes
	view       *mailstore.View // selected folder
}

var _ imapserver.SessionIMAP4rev2 = (*session)(nil)

func newSession(conn *imapserver.Conn) *session {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	s := &session{id: hex.EncodeToString(b), remote: conn.NetConn().RemoteAddr().String()}
	s.logf("starting new session")
	if core.Cfg.GetDebugEnabled() {
		debug := func(line string) { core.Logger.Debug(s.prefix() + line) }
		conn.SetDebug(&protoLog{dir: "< ", client: true, log: debug}, &protoLog{dir: "> ", log: debug})
	}
	return s
}

func (s *session) prefix() string {
	return fmt.Sprintf("imapd %s-%s-", s.id, s.remote)
}

func (s *session) logf(format string, a ...interface{}) {
	core.Logger.Info(s.prefix() + fmt.Sprintf(format, a...))
}

func (s *session) errorf(format string, a ...interface{}) {
	core.Logger.Error(s.prefix() + fmt.Sprintf(format, a...))
}

// internal errors are logged, the client only gets a generic error
func (s *session) internal(what string, err error) error {
	if _, ok := err.(*imap.Error); ok {
		return err
	}
	s.errorf("%s: %s", what, err)
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeServerBug, Text: "Server error, see the cocosmail log"}
}

func (s *session) Close() error {
	if s.view != nil {
		s.view.Close()
		s.view = nil
	}
	s.logf("EOT")
	return nil
}

// failed logins wait, to slow down password guessing
var loginFailDelay = time.Second

func (s *session) Login(username, password string) error {
	usr, err := core.UserGet(username, password)
	if err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			s.logf("authentication failed for user %s: user not found", username)
		case bcrypt.ErrMismatchedHashAndPassword:
			s.logf("authentication failed for user %s: wrong password", username)
		default:
			s.logf("authentication failed for user %s: %s", username, err)
		}
		time.Sleep(loginFailDelay)
		return imapserver.ErrAuthFailed
	}
	if !usr.HaveMailbox {
		s.logf("authentication failed for user %s: no mailbox", username)
		time.Sleep(loginFailDelay)
		return imapserver.ErrAuthFailed
	}
	s.boxes = mailstore.Mailboxes{Home: usr.HomePath()}
	if err := s.boxes.Init(); err != nil {
		return s.internal("mailbox of "+username, err)
	}
	s.user = usr.Login
	s.logf("user %s logged in", s.user)
	return nil
}

// folder returns the directory of an existing folder
func (s *session) folder(name string, notFound error) (string, error) {
	if !s.boxes.Exists(name) {
		return "", notFound
	}
	return s.boxes.Path(name)
}

func (s *session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if s.view != nil {
		s.view.Close()
		s.view = nil
	}
	p, err := s.folder(name, mailstore.ErrNoMailbox)
	if err != nil {
		return nil, err
	}
	view, data, err := mailstore.Select(p, options.ReadOnly)
	if err != nil {
		return nil, s.internal("select "+name, err)
	}
	s.view = view
	return data, nil
}

func (s *session) Unselect() error {
	if s.view != nil {
		s.view.Close()
		s.view = nil
	}
	return nil
}

func (s *session) Create(name string, options *imap.CreateOptions) error {
	if err := s.boxes.Create(name); err != nil {
		return s.internal("create "+name, err)
	}
	return nil
}

func (s *session) Delete(name string) error {
	if err := s.boxes.Delete(name); err != nil {
		return s.internal("delete "+name, err)
	}
	return nil
}

func (s *session) Rename(name, newName string, options *imap.RenameOptions) error {
	if err := s.boxes.Rename(name, newName); err != nil {
		return s.internal("rename "+name, err)
	}
	return nil
}

func (s *session) Subscribe(name string) error {
	return s.boxes.SetSubscribed(name, true)
}

func (s *session) Unsubscribe(name string) error {
	return s.boxes.SetSubscribed(name, false)
}

func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: mailstore.Delim})
	}
	all, err := s.boxes.List()
	if err != nil {
		return s.internal("list", err)
	}
	subs := s.boxes.Subscriptions()
	for _, name := range all {
		match := false
		for _, pattern := range patterns {
			if imapserver.MatchList(name, mailstore.Delim, ref, pattern) {
				match = true
				break
			}
		}
		special := mailstore.SpecialUse(name)
		if !match || options.SelectSubscribed && !subs[name] || options.SelectSpecialUse && special == "" {
			continue
		}
		data := imap.ListData{Mailbox: name, Delim: mailstore.Delim}
		if s.boxes.HasChildren(name, all) {
			data.Attrs = append(data.Attrs, imap.MailboxAttrHasChildren)
		} else {
			data.Attrs = append(data.Attrs, imap.MailboxAttrHasNoChildren)
		}
		if subs[name] && (options.SelectSubscribed || options.ReturnSubscribed) {
			data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
		}
		if special != "" {
			data.Attrs = append(data.Attrs, special)
		}
		if options.ReturnStatus != nil {
			if data.Status, err = s.Status(name, options.ReturnStatus); err != nil {
				return err
			}
		}
		if err := w.WriteList(&data); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	p, err := s.folder(name, mailstore.ErrNoMailbox)
	if err != nil {
		return nil, err
	}
	f, err := mailstore.Open(p)
	if err != nil {
		return nil, s.internal("status "+name, err)
	}
	defer f.Close()
	data := f.Status(options)
	data.Mailbox = mailstore.CanonicalName(name)
	return data, nil
}

func (s *session) Append(name string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	p, err := s.folder(name, mailstore.ErrTryCreate)
	if err != nil {
		return nil, err
	}
	f, err := mailstore.Open(p)
	if err != nil {
		return nil, s.internal("append to "+name, err)
	}
	defer f.Close()
	uid, err := f.Append(r, options.Flags, options.Time)
	if err != nil {
		return nil, s.internal("append to "+name, err)
	}
	return &imap.AppendData{UID: uid, UIDValidity: f.Validity()}, nil
}

func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.view == nil {
		return nil
	}
	return s.view.Poll(w, allowExpunge)
}

func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.view == nil {
		return nil
	}
	return s.view.Idle(w, stop)
}

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	return s.view.Expunge(w, uids)
}

func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	return s.view.Search(kind, criteria, options)
}

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	return s.view.Fetch(w, numSet, options)
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	return s.view.Store(w, numSet, flags, options)
}

func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	p, err := s.folder(dest, mailstore.ErrTryCreate)
	if err != nil {
		return nil, err
	}
	f, err := mailstore.Open(p)
	if err != nil {
		return nil, s.internal("copy to "+dest, err)
	}
	defer f.Close()
	data, err := s.view.Copy(numSet, f)
	if err != nil {
		return nil, s.internal("copy to "+dest, err)
	}
	return data, nil
}

func (s *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	p, err := s.folder(dest, mailstore.ErrTryCreate)
	if err != nil {
		return err
	}
	f, err := mailstore.Open(p)
	if err != nil {
		return s.internal("move to "+dest, err)
	}
	defer f.Close()
	if err := s.view.Move(w, numSet, f); err != nil {
		return s.internal("move to "+dest, err)
	}
	return nil
}

func (s *session) Namespace() (*imap.NamespaceData, error) {
	return &imap.NamespaceData{
		Personal: []imap.NamespaceDescriptor{{Delim: mailstore.Delim}},
	}, nil
}

// logger logs errors of the IMAP library
type logger struct{}

func (logger) Printf(format string, a ...interface{}) {
	core.Logger.Error("imapd " + fmt.Sprintf(format, a...))
}

var (
	listeners   []net.Listener
	listenersMu sync.Mutex
	// connections being served
	clients int64
)

// Close stops accepting IMAP connections, clients being served go on
func Close() {
	listenersMu.Lock()
	defer listenersMu.Unlock()
	for _, l := range listeners {
		l.Close()
	}
	listeners = nil
}

// at a restart, IMAP clients stay connected (IDLE) and reconnect: only
// commands in progress are waited for, a few seconds
var maxWait = 5 * time.Second

// Wait waits up to timeout for IMAP clients being served
func Wait(timeout time.Duration) {
	if timeout > maxWait {
		timeout = maxWait
	}
	deadline := time.Now().Add(timeout)
	for atomic.LoadInt64(&clients) > 0 {
		if time.Now().After(deadline) {
			core.Logger.Info("imapd: clients still connected, they'll reconnect")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Imapd is an IMAP listener
type Imapd struct {
	dsn core.Dsn
}

// NewImapd returns an IMAP listener for dsn
func NewImapd(d core.Dsn) *Imapd {
	return &Imapd{d}
}

// ListenAndServe launches the IMAP server. With ssl, connections are
// encrypted from the start, else STARTTLS is offered and login needs it,
// except on loopback (behind a TLS proxy).
func (d *Imapd) ListenAndServe() {
	cert, err := tls.LoadX509KeyPair(
		path.Join(core.Cfg.GetBasePath(), fmt.Sprintf("ssl/imap-%s.crt", d.dsn.CertName)),
		path.Join(core.Cfg.GetBasePath(), fmt.Sprintf("ssl/imap-%s.key", d.dsn.CertName)))
	if err != nil {
		log.Fatalln("unable to load SSL keys for imap.", "err:", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	options := &imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return newSession(conn), nil, nil
		},
		Caps:   caps,
		Logger: logger{},
	}
	if !d.dsn.Ssl {
		options.TLSConfig = tlsConfig
		options.InsecureAuth = d.dsn.TcpAddr.IP.IsLoopback()
	}

	raw, err := net.Listen("tcp", d.dsn.TcpAddr.String())
	if err != nil {
		log.Fatalln("unable to launch imap server", d.dsn.String(), "-", err)
	}
	listenersMu.Lock()
	listeners = append(listeners, raw)
	listenersMu.Unlock()
	// counted under TLS: the library must see *tls.Conn to allow login
	var ln net.Listener = countingListener{raw}
	if d.dsn.Ssl {
		ln = tls.NewListener(ln, tlsConfig)
	}

	core.Logger.Info("imapd " + d.dsn.String() + " launched")
	if err := imapserver.New(options).Serve(ln); err != nil {
		core.Logger.Error("imapd " + d.dsn.String() + ": " + err.Error())
	}
}

// countingListener counts the connections being served, for Wait
type countingListener struct {
	net.Listener
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	atomic.AddInt64(&clients, 1)
	return &countedConn{Conn: c}, nil
}

type countedConn struct {
	net.Conn
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { atomic.AddInt64(&clients, -1) })
	return c.Conn.Close()
}
