package pop3

import (
	"crypto/md5"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/cocosmail/imap/goimap"
	"github.com/stunndard/cocosmail/mailstore"
	"github.com/stunndard/cocosmail/pop3/popgun"
	"golang.org/x/crypto/bcrypt"
)

type Message struct {
	msg     mailstore.Message
	key     string
	size    int
	deleted bool
}

// Session is the POP3 session of a user: one at a time per user. Messages are
// those of INBOX at login, IMAP sessions and deliveries can change it
// meanwhile: everything goes through mailstore.
type Session struct {
	messages []*Message
	user     string
	inbox    *mailstore.Folder
}

var (
	sessions   = make(map[string]*Session)
	sessionsMu sync.Mutex
)

func GetSession(user string) (session *Session, err error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	session, found := sessions[user]
	if !found {
		return session, errors.New("session not found")
	}
	return session, nil
}

// read returns the content of a message, an error if it was deleted
// meanwhile, e.g. by an IMAP session
func (s *Session) read(msg *Message) (string, error) {
	b, err := s.inbox.Read(msg.msg)
	if err == mailstore.ErrExpunged {
		return "", errors.New("message deleted meanwhile by another session")
	}
	if err != nil {
		core.Logger.Error(fmt.Sprintf("pop3d user %s error reading message %s: %s", s.user, msg.key, err))
		return "", errors.New("error reading message")
	}
	return string(b), nil
}

// Authorizator is a authorizator interface implementation
type Authorizator struct {
}

// Authorize user for given username and password.
func (a Authorizator) Authorize(user, pass string) bool {
	usr, err := core.UserGet(user, pass)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			core.Logger.Info(fmt.Sprintf("pop3d authentication failed for user %s: user not found", user))
			return false
		}
		if err == bcrypt.ErrMismatchedHashAndPassword {
			core.Logger.Info(fmt.Sprintf("pop3d authentication failed for user %s: wrong password", user))
			return false
		}
		core.Logger.Info(fmt.Sprintf("pop3d authentication failed for user %s: %s", user, err))
		return false
	}
	if usr.Login != user {
		core.Logger.Error(fmt.Sprintf("pop3d authentication failed for user %s: wrong user fetched: %s", user, usr.Login))
		return false
	}
	return true
}

// Backend is a backend interface implementation
type Backend struct{}

func NewBackend() *Backend {
	return &Backend{}
}

// Returns total message count and total mailbox size in bytes (octets).
// Deleted messages are ignored.
func (b *Backend) Stat(user string) (messages, octets int, err error) {
	s, _ := GetSession(user)

	total := 0
	numMsg := 0
	for _, msg := range s.messages {
		if !msg.deleted {
			total = total + msg.size
			numMsg = numMsg + 1
		}
	}

	return numMsg, total, nil
}

// List of sizes of all messages in bytes (octets)
func (b *Backend) List(user string) (octets []int, err error) {
	s, _ := GetSession(user)

	for _, msg := range s.messages {
		if msg.deleted {
			octets = append(octets, 0)
		} else {
			octets = append(octets, msg.size)
		}
	}

	return octets, nil
}

// Returns whether message exists and if yes, then return size of the message in bytes (octets)
func (b *Backend) ListMessage(user string, msgId int) (exists bool, octets int, err error) {
	s, _ := GetSession(user)

	if len(s.messages) == 0 || (msgId < 1 || msgId > len(s.messages)) {
		return false, 0, errors.New("invalid message id")
	}

	msg := s.messages[msgId-1]
	if msg.deleted {
		return false, 0, errors.New("message already deleted")
	}

	return true, msg.size, nil
}

// Retrieve whole message by ID - note that message ID is a message position returned
// by List() function, so be sure to keep that order unchanged while client is connected
// See Lock() function for more details
func (b *Backend) Retr(user string, msgId int) (message string, err error) {
	s, _ := GetSession(user)

	if len(s.messages) == 0 || (msgId < 1 || msgId > len(s.messages)) {
		return message, errors.New("invalid message id")
	}
	msg := s.messages[msgId-1]

	if msg.deleted {
		return message, errors.New("message already deleted")
	}

	return s.read(msg)
}

// Delete message by message ID - message should be just marked as deleted until
// Update() is called. Be aware that after Dele() is called, functions like List() etc.
// should ignore all these messages even if Update() hasn't been called yet
func (b *Backend) Dele(user string, msgId int) error {
	s, _ := GetSession(user)

	if len(s.messages) == 0 || (msgId < 1 || msgId > len(s.messages)) {
		return fmt.Errorf("%w", errors.New("invalid message id"))
	}
	msg := s.messages[msgId-1]
	if msg.deleted {
		return errors.New("message already deleted")
	}
	msg.deleted = true

	return nil
}

// Undelete all messages marked as deleted in single connection
func (b *Backend) Rset(user string) error {
	s, _ := GetSession(user)

	for _, msg := range s.messages {
		msg.deleted = false
	}

	return nil
}

// List of unique IDs of all message, similar to List(), but instead of size there
// is a unique ID which persists the same across all connections. Uid (unique id) is
// used to allow client to be able to keep messages on the server.
func (b *Backend) Uidl(user string) (uids []string, err error) {
	s, _ := GetSession(user)

	for _, msg := range s.messages {
		if msg.deleted {
			uids = append(uids, "")
		} else {
			uids = append(uids, fmt.Sprintf("%x", md5.Sum([]byte(msg.key))))
		}
	}

	return uids, nil
}

// Similar to ListMessage, but returns unique ID by message ID instead of size.
func (b *Backend) UidlMessage(user string, msgId int) (exists bool, uid string, err error) {
	s, _ := GetSession(user)

	if len(s.messages) == 0 || (msgId < 1 || msgId > len(s.messages)) {
		return false, uid, errors.New("invalid message id")
	}

	msg := s.messages[msgId-1]
	if msg.deleted {
		return false, uid, errors.New("message already deleted")
	}

	return true, fmt.Sprintf("%x", md5.Sum([]byte(msg.key))), nil
}

// Similar to TopMessage, but returns unique ID by message ID instead of size.
func (b *Backend) TopMessage(user string, msgId, msgLines int) (exists bool, message string, err error) {
	s, _ := GetSession(user)

	if len(s.messages) == 0 || (msgId < 1 || msgId > len(s.messages)) {
		return false, message, errors.New("invalid message id")
	}

	if msgLines < 0 {
		return false, message, errors.New("invalid lines")
	}

	msg := s.messages[msgId-1]
	if msg.deleted {
		return false, message, errors.New("message already deleted")
	}

	buf, err := s.read(msg)
	if err != nil {
		return false, message, err
	}

	lines := strings.Split(buf, "\n")
	out := make([]string, 0)
	i := 0
	body := false
	for _, line := range lines {
		out = append(out, line)
		if !body {
			if line == "\r" {
				body = true
				if msgLines == 0 {
					break
				}
			}
		} else {
			i++
			if i >= msgLines {
				break
			}
		}
	}
	message = strings.Join(out, "\n")
	return true, message, nil
}

// Write all changes to persistent storage, i.e. delete all messages marked as deleted.
func (b *Backend) Update(user string) error {
	s, _ := GetSession(user)

	var uids []imap.UID
	for _, msg := range s.messages {
		if msg.deleted {
			uids = append(uids, msg.msg.UID)
		}
	}
	if len(uids) == 0 {
		return nil
	}
	i, err := s.inbox.Remove(uids)
	if err != nil {
		core.Logger.Error(fmt.Sprintf("pop3d user %s error deleting messages: %s", user, err))
	}

	core.Logger.Info(fmt.Sprintf("pop3d user %s updated mailbox, deleted %d messages", user, i))

	return err
}

// Lock is called immediately after client is connected. The best way what to use Lock() for
// is to read all the messages into cache after client is connected. If another user
// tries to lock the storage, you should return an error to avoid data race.
// Only one POP3 session per user at a time: in memory, so no stale lock after
// a crash. IMAP sessions share the mailbox, through mailstore.
func (b *Backend) Lock(user string) (inUse bool, err error) {
	sessionsMu.Lock()
	if _, ok := sessions[user]; ok {
		sessionsMu.Unlock()
		return true, nil
	}
	s := &Session{user: user}
	sessions[user] = s
	sessionsMu.Unlock()
	defer func() {
		if err != nil {
			b.Unlock(user)
		}
	}()

	usr, err := core.UserGetByLogin(user)
	if err != nil {
		return false, fmt.Errorf("cannot get user: %s: %w", user, err)
	}
	home := usr.HomePath()
	if err = os.MkdirAll(home, 0700); err != nil {
		return false, fmt.Errorf("cannot create mailbox dir for user %s: %w", user, err)
	}
	if s.inbox, err = mailstore.Open(home); err != nil {
		return false, fmt.Errorf("cannot open mailbox of user %s: %w", user, err)
	}
	core.Logger.Info(fmt.Sprintf("pop3d user %s locked mailbox", user))

	msgs, err := s.inbox.Messages()
	if err != nil {
		return false, fmt.Errorf("cannot read mailbox of user %s: %w", user, err)
	}
	for _, m := range msgs {
		s.messages = append(s.messages, &Message{msg: m, key: m.Key, size: int(m.Size)})
	}

	core.Logger.Info(fmt.Sprintf("pop3d user %s loaded %d messages", user, len(s.messages)))

	return false, nil
}

// Release lock on storage, Unlock() is called after client is disconnected.
func (b *Backend) Unlock(user string) error {
	sessionsMu.Lock()
	s := sessions[user]
	delete(sessions, user)
	sessionsMu.Unlock()
	if s != nil && s.inbox != nil {
		s.inbox.Close()
	}

	core.Logger.Info(fmt.Sprintf("pop3d user %s unlocked mailbox", user))

	return nil
}

// ClearLocks deletes the lock files older versions left in users mail
// directories: locks are kept in memory now.
// It's caled at pop3 server start only.
func (b *Backend) ClearLocks() error {
	// get all users
	usrs, err := core.UserList()
	if err != nil {
		return fmt.Errorf("cannot get users: %w", err)
	}

	for _, usr := range usrs {
		if !usr.HaveMailbox {
			continue
		}
		lockfile := usr.HomePath() + "/lock"
		if _, err = os.Stat(lockfile); err != nil {
			continue
		}
		if err := os.Remove(lockfile); err != nil {
			return fmt.Errorf("error removing lockfile: %w", err)
		}
		core.Logger.Info(fmt.Sprintf("stalled lockfile removed %s", lockfile))
	}

	return nil
}

// Log should implement any backend specific logging
// Session lines are ID-REMOTE-message, like smtpd.
func (b *Backend) Log(s string, loglevel int) {
	switch loglevel {
	case popgun.LOG_INFO:
		core.Logger.Info("pop3d ", s)
	case popgun.LOG_ERROR:
		core.Logger.Error("pop3d ", s)
	default:
		core.Logger.Debug("pop3d ", s)
	}
}

// ClearLocks deletes stuck lock files left by a previous run.
// Must be called once before launching pop3 servers.
func ClearLocks() error {
	return NewBackend().ClearLocks()
}

// pop3 Server
type Pop3d struct {
	dsn core.Dsn
}

var (
	servers   []*popgun.Server
	serversMu sync.Mutex
)

// Close stops accepting POP3 connections, clients being served go on
func Close() {
	serversMu.Lock()
	defer serversMu.Unlock()
	for _, s := range servers {
		s.Close()
	}
}

// Wait waits up to timeout for POP3 clients being served
func Wait(timeout time.Duration) {
	serversMu.Lock()
	list := servers
	serversMu.Unlock()
	deadline := time.Now().Add(timeout)
	for _, s := range list {
		if !s.Wait(time.Until(deadline)) {
			core.Logger.Info("pop3d: clients still connected, they'll reconnect")
			return
		}
	}
}

// NewPop3d returns a new SmtpServer
func NewPop3d(d core.Dsn) *Pop3d {
	return &Pop3d{d}
}

// ListenAndServe launches pop3 server
func (p *Pop3d) ListenAndServe() {

	var authorizator Authorizator

	backend := NewBackend()

	pop3Cfg := &popgun.Config{
		ListenInterface: p.dsn.TcpAddr.String(),
		ServerName:      fmt.Sprintf("cocosmail %s at %s", core.CocosmailVersion, p.dsn.SystemName),
	}

	if p.dsn.Ssl {
		cert, err := tls.LoadX509KeyPair(
			path.Join(core.Cfg.GetBasePath(), fmt.Sprintf("ssl/pop3-%s.crt", p.dsn.CertName)),
			path.Join(core.Cfg.GetBasePath(), fmt.Sprintf("ssl/pop3-%s.key", p.dsn.CertName)))
		if err != nil {
			log.Fatalln("unable to load SSL keys for pop3.", "err:", err)
		}
		// TODO: http://fastah.blackbuck.mobi/blog/securing-https-in-go/
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		pop3Cfg.UseTls = true
		pop3Cfg.TlsConfig = tlsConfig
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	server := popgun.NewServer(pop3Cfg, authorizator, backend)
	err := server.Start()
	if err != nil {
		log.Fatalln("unable to launch pop3 server", p.dsn.String(), "-", err)
	}
	serversMu.Lock()
	servers = append(servers, server)
	serversMu.Unlock()

	core.Logger.Info("pop3d " + p.dsn.String() + " launched")

	<-sigChan

	core.Logger.Info("pop3d exiting")
}
