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
	"syscall"

	"github.com/jinzhu/gorm"
	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/go-maildir"
	"github.com/stunndard/popgun"
)

type Message struct {
	filename string
	key      string
	size     int
	deleted  bool
}

func NewMessage(filename, key string, size int) *Message {
	return &Message{
		filename: filename,
		key:      key,
		size:     size,
	}
}

type Session struct {
	messages []*Message
	user     string
	md       maildir.Dir
}

var sessions = make(map[string]*Session)

func NewSession(user string, s *Session) *Session {
	sessions[user] = s
	return s
}

func DeleteSession(user string) {
	delete(sessions, user)
}

func GetSession(user string) (session *Session, err error) {
	var found bool
	session, found = sessions[user]
	if !found {
		return session, errors.New("session not found")
	}
	return session, nil
}

// Authorizator is a authorizator interface implementation
type Authorizator struct {
}

// Authorize user for given username and password.
func (a Authorizator) Authorize(user, pass string) bool {
	_, err := core.UserGet(user, pass)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			core.Logger.Info(fmt.Sprintf("pop3d authentication failed for user %s: user not found", user))
			return false
		}
		if err.Error() == "crypto/bcrypt: hashedPassword is not the hash of the given password" {
			core.Logger.Info(fmt.Sprintf("pop3d authentication failed for user %s: wrong password", user))
			return false
		}
	}
	return true
}

type Config struct {
	mailDirPath string
}

// Backend is a backend interface implementation
type Backend struct {
	config Config
}

func NewBackend(cfg Config) *Backend {
	return &Backend{
		config: cfg,
	}
}

// Returns total message count and total mailbox size in bytes (octets).
// Deleted messages are ignored.
func (b *Backend) Stat(user string) (messages, octets int, err error) {
	s, _ := GetSession(user)

	/*
		fmt.Println("current maildir", s.md)
		fmt.Println("current user", s.user)
	*/

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

	r, err := s.md.Open(msg.key)
	defer func() {
		_ = r.Close()
	}()
	if err != nil {
		return message, errors.New("error opening")
	}

	buf := make([]byte, msg.size)
	read, err := r.Read(buf)
	if err != nil {
		return message, errors.New("error read")
	}
	if read != msg.size {
		return message, errors.New("error size")
	}

	return string(buf), nil
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

	r, err := s.md.Open(msg.key)
	defer func() {
		_ = r.Close()
	}()
	if err != nil {
		return false, message, errors.New("error opening")
	}

	buf := make([]byte, msg.size)
	read, err := r.Read(buf)
	if err != nil {
		return false, message, errors.New("error read")
	}
	if read != msg.size {
		return false, message, errors.New("error size")
	}

	lines := strings.Split(string(buf), "\n")
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

	i := 0
	for _, msg := range s.messages {
		if msg.deleted {
			err := s.md.Remove(msg.key)
			if err != nil {
				core.Logger.Info(fmt.Sprintf("pop3d user %s error deleting file %s: %s", user, msg.filename, err))
			}
			i++
		}
	}

	core.Logger.Info(fmt.Sprintf("pop3d user %s updated mailbox, deleted %d messages", user, i))

	return nil
}

// Lock is called immediately after client is connected. The best way what to use Lock() for
// is to read all the messages into cache after client is connected. If another user
// tries to lock the storage, you should return an error to avoid data race.
func (b *Backend) Lock(user string) (inUse bool, err error) {
	// get the user
	usr, err := core.UserGetByLogin(user)
	if err != nil {
		return false, fmt.Errorf("cannot get user: %s: %w", user, err)
	}
	// get user home path
	mdUserHome := usr.Home
	_, err = os.Stat(mdUserHome)
	if err != nil {
		err = os.MkdirAll(mdUserHome, 0700)
		if err != nil {
			return false, fmt.Errorf("cannot create mailbox dir for user %s: %w", user, err)
		}
	}

	lockfile := mdUserHome + "/lock"
	_, err = os.Stat(lockfile)
	if err == nil {
		return true, nil
	}
	f, err := os.Create(lockfile)
	if err != nil {
		return false, fmt.Errorf("cannot create lock: %w", err)
	}
	_ = f.Close()

	s := NewSession(user, &Session{
		user: user,
		md:   maildir.Dir(mdUserHome),
	})

	core.Logger.Info(fmt.Sprintf("pop3d user %s locked mailbox", user))

	err = s.md.Init()
	if err != nil {
		return false, fmt.Errorf("error maildir.Init: %w", err)
	}
	uns, err := s.md.UnseenCount()
	if err != nil {
		return false, fmt.Errorf("error maildir.UnseenCount: %w", err)
	}
	core.Logger.Info(fmt.Sprintf("pop3d user %s has %d unseen messages", user, uns))
	unseen, err := s.md.Unseen()
	if err != nil {
		return false, fmt.Errorf("error maildir.Unseen: %w", err)
	}
	core.Logger.Info(fmt.Sprintf("pop3d user %s moved %d messages from new to cur", user, len(unseen)))

	keys, err := s.md.Keys()
	if err != nil {
		return false, errors.New("error maildir.Keys()")
	}
	for _, key := range keys {
		filename, err := s.md.Filename(key)
		if err != nil {
			return false, errors.New("error maildir.Filename()")
		}
		fi, err := os.Stat(filename)
		if err != nil {
			return false, errors.New("error os.Stat()")
		}
		filesize := int(fi.Size())

		m := NewMessage(filename, key, filesize)
		s.messages = append(s.messages, m)
	}

	core.Logger.Info(fmt.Sprintf("pop3d user %s loaded %d messages", user, len(s.messages)))

	return false, nil
}

// Release lock on storage, Unlock() is called after client is disconnected.
func (b *Backend) Unlock(user string) error {
	// even if cannot unlock after, better to delete session
	// so it remains locked and cannot be entered again
	DeleteSession(user)

	lockfile := b.config.mailDirPath + "/" + user + "/lock"
	if err := os.Remove(lockfile); err != nil {
		return fmt.Errorf("error unlocking user: %w", err)
	}

	core.Logger.Info(fmt.Sprintf("pop3d user %s unlocked mailbox", user))

	return nil
}

// ClearLocks deletes all stuck lock files in all users mail directories.
// It's caled at pop3 server start only.
func (b *Backend) ClearLocks() error {
	f, err := os.Open(b.config.mailDirPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dirs, err := f.Readdir(0)
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		lockfile := b.config.mailDirPath + "/" + dir.Name() + "/lock"
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
func (b *Backend) Log(s string, loglevel int) {
	core.Logger.Debug("pop3d ", s)
}

// pop3 Server
type Pop3d struct {
	dsn core.Dsn
}

// NewPop3d returns a new SmtpServer
func NewPop3d(d core.Dsn) *Pop3d {
	return &Pop3d{d}
}

// ListenAndServe launches pop3 server
func (p *Pop3d) ListenAndServe() {

	var authorizator Authorizator

	backend := NewBackend(Config{
		mailDirPath: core.Cfg.GetUsersHomeBase(),
	})

	if err := backend.ClearLocks(); err != nil {
		log.Fatal(err)
	}

	pop3Cfg := &popgun.Config{
		ListenInterface: p.dsn.TcpAddr.String(),
		ServerName:      fmt.Sprintf("cocosmail %s at %s", core.CocosmailVersion, p.dsn.SystemName),
	}

	if p.dsn.Ssl {
		cert, err := tls.LoadX509KeyPair(
			path.Join(core.Cfg.GetBasePath(), fmt.Sprintf("ssl/pop3-%s.crt", p.dsn.CertName)),
			path.Join(core.Cfg.GetBasePath(), fmt.Sprintf("ssl/pop3-%s.key", p.dsn.CertName,
			)))
		if err != nil {
			log.Fatalln("unable to load SSL keys for pop3.", "err:", err)
		}
		// TODO: http://fastah.blackbuck.mobi/blog/securing-https-in-go/
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}
		pop3Cfg.UseTls = true
		pop3Cfg.TlsConfig = tlsConfig
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	server := popgun.NewServer(pop3Cfg, authorizator, backend)
	err := server.Start()
	if err != nil {
		log.Fatal("unable to launch pop3 server")
	}

	core.Logger.Info("pop3d " + p.dsn.String() + " launched")

	<-sigChan

	core.Logger.Info("pop3d exiting")
}
