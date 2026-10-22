package mailstore

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/stunndard/cocosmail/imap/goimap"
)

// Delim separates folder levels: Archive.2024 is directory .Archive.2024
const Delim = '.'

// Inbox is the name of the user's home Maildir
const Inbox = "INBOX"

const subscriptionsFile = "subscriptions"

// folders created at the first login, with their special use (RFC 6154)
var defaultFolders = []string{"Drafts", "Sent", "Trash", "Junk", "Archive"}

var specialUses = map[string]imap.MailboxAttr{
	"drafts":           imap.MailboxAttrDrafts,
	"sent":             imap.MailboxAttrSent,
	"sent items":       imap.MailboxAttrSent,
	"sent messages":    imap.MailboxAttrSent,
	"trash":            imap.MailboxAttrTrash,
	"deleted items":    imap.MailboxAttrTrash,
	"deleted messages": imap.MailboxAttrTrash,
	"junk":             imap.MailboxAttrJunk,
	"spam":             imap.MailboxAttrJunk,
	"archive":          imap.MailboxAttrArchive,
}

// SpecialUse returns the special use of a folder, from its name, or ""
func SpecialUse(name string) imap.MailboxAttr {
	return specialUses[strings.ToLower(name)]
}

var (
	// ErrNoMailbox is returned for a folder that doesn't exist
	ErrNoMailbox = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
	errExists    = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAlreadyExists, Text: "Mailbox already exists"}
	// ErrTryCreate is ErrNoMailbox where the client may create the folder
	ErrTryCreate = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	errInUse     = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeInUse, Text: "Mailbox is in use, close it in your other mail programs first"}
)

func noMailbox(text string) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: text}
}

// Mailboxes are the folders of a user
type Mailboxes struct {
	Home string
}

// changes of folders and subscriptions, one at a time per user
var (
	homeLocksMu sync.Mutex
	homeLocks   = make(map[string]*sync.Mutex)
)

func (b Mailboxes) lock() func() {
	homeLocksMu.Lock()
	l := homeLocks[b.Home]
	if l == nil {
		l = &sync.Mutex{}
		homeLocks[b.Home] = l
	}
	homeLocksMu.Unlock()
	l.Lock()
	return l.Unlock
}

// CanonicalName returns INBOX for inbox in any case
func CanonicalName(name string) string {
	if strings.EqualFold(name, Inbox) {
		return Inbox
	}
	return name
}

func validName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\\") || name[0] == Delim || name[len(name)-1] == Delim ||
		strings.Contains(name, string([]rune{Delim, Delim})) {
		return noMailbox("Invalid mailbox name")
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f {
			return noMailbox("Invalid mailbox name")
		}
	}
	return nil
}

// Path returns the directory of folder name
func (b Mailboxes) Path(name string) (string, error) {
	name = CanonicalName(name)
	if name == Inbox {
		return b.Home, nil
	}
	if err := validName(name); err != nil {
		return "", err
	}
	return filepath.Join(b.Home, string(Delim)+name), nil
}

// Exists tells if folder name exists
func (b Mailboxes) Exists(name string) bool {
	p, err := b.Path(name)
	return err == nil && isMaildir(p)
}

// List returns the folder names, INBOX first
func (b Mailboxes) List() ([]string, error) {
	entries, err := os.ReadDir(b.Home)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if len(n) < 2 || n[0] != Delim || n == ".." || !e.IsDir() {
			continue
		}
		if validName(n[1:]) == nil && isMaildir(filepath.Join(b.Home, n)) {
			names = append(names, n[1:])
		}
	}
	sort.Strings(names)
	return append([]string{Inbox}, names...), nil
}

// HasChildren tells if folder name has subfolders
func (b Mailboxes) HasChildren(name string, all []string) bool {
	for _, n := range all {
		if strings.HasPrefix(n, name+string(Delim)) {
			return true
		}
	}
	return false
}

// Create creates folder name, and its parents
func (b Mailboxes) Create(name string) error {
	defer b.lock()()
	return b.createLocked(name)
}

func (b Mailboxes) createLocked(name string) error {
	name = CanonicalName(strings.TrimRight(name, string(Delim)))
	if b.Exists(name) {
		return errExists
	}
	if _, err := b.Path(name); err != nil {
		return err
	}
	parts := strings.Split(name, string(Delim))
	for i := range parts {
		p, _ := b.Path(strings.Join(parts[:i+1], string(Delim)))
		if err := initMaildir(p); err != nil {
			return err
		}
	}
	return nil
}

// Delete deletes folder name and its messages. A folder with subfolders or
// in use can't be deleted.
func (b Mailboxes) Delete(name string) error {
	defer b.lock()()
	name = CanonicalName(name)
	if name == Inbox {
		return noMailbox("INBOX can't be deleted")
	}
	p, err := b.Path(name)
	if err != nil {
		return err
	}
	if !isMaildir(p) {
		return ErrNoMailbox
	}
	all, err := b.List()
	if err != nil {
		return err
	}
	if b.HasChildren(name, all) {
		return noMailbox("Mailbox has subfolders, delete them first")
	}
	if isOpen(p) {
		return errInUse
	}
	if err := os.RemoveAll(p); err != nil {
		return err
	}
	return b.setSubscribedLocked(name, false)
}

// Rename renames folder old and its subfolders. Renaming INBOX moves its
// messages to the new folder.
func (b Mailboxes) Rename(old, new string) error {
	defer b.lock()()
	old, new = CanonicalName(old), CanonicalName(strings.TrimRight(new, string(Delim)))
	oldPath, err := b.Path(old)
	if err != nil {
		return err
	}
	if !isMaildir(oldPath) {
		return ErrNoMailbox
	}
	if new == Inbox || b.Exists(new) {
		return errExists
	}
	newPath, err := b.Path(new)
	if err != nil {
		return err
	}
	if old == Inbox {
		return b.moveInbox(new, newPath)
	}
	if isOpen(oldPath) {
		return errInUse
	}
	all, err := b.List()
	if err != nil {
		return err
	}
	if i := strings.LastIndexByte(new, Delim); i > 0 {
		if err := b.createLocked(new[:i]); err != nil && err != errExists {
			return err
		}
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	subs := b.subscriptions()
	for _, n := range all {
		if !strings.HasPrefix(n, old+string(Delim)) {
			continue
		}
		child := new + n[len(old):]
		from, _ := b.Path(n)
		to, _ := b.Path(child)
		if err := os.Rename(from, to); err != nil {
			return err
		}
		if subs[n] {
			delete(subs, n)
			subs[child] = true
		}
	}
	if subs[old] {
		delete(subs, old)
		subs[new] = true
	}
	return b.writeSubscriptions(subs)
}

// moveInbox moves the messages of INBOX to a new folder
func (b Mailboxes) moveInbox(name, path string) error {
	if err := b.createLocked(name); err != nil {
		return err
	}
	inbox, err := Open(b.Home)
	if err != nil {
		return err
	}
	defer inbox.Close()
	inbox.mu.Lock()
	defer inbox.mu.Unlock()
	if err := inbox.syncLocked(); err != nil {
		return err
	}
	for _, m := range inbox.msgs {
		err := os.Rename(filepath.Join(b.Home, "cur", m.name), filepath.Join(path, "cur", m.name))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	// cur/ changed: the messages are expunged for the sessions
	return inbox.syncLocked()
}

func (b Mailboxes) subscriptions() map[string]bool {
	subs := make(map[string]bool)
	f, err := os.Open(filepath.Join(b.Home, subscriptionsFile))
	if err != nil {
		return subs
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if n := strings.TrimSpace(s.Text()); n != "" {
			subs[CanonicalName(n)] = true
		}
	}
	return subs
}

func (b Mailboxes) writeSubscriptions(subs map[string]bool) error {
	var names []string
	for n := range subs {
		names = append(names, n)
	}
	sort.Strings(names)
	data := strings.Join(names, "\n")
	if data != "" {
		data += "\n"
	}
	return writeFileAtomic(filepath.Join(b.Home, subscriptionsFile), []byte(data))
}

// Subscriptions returns the subscribed folders
func (b Mailboxes) Subscriptions() map[string]bool {
	defer b.lock()()
	return b.subscriptions()
}

// SetSubscribed subscribes or unsubscribes folder name
func (b Mailboxes) SetSubscribed(name string, on bool) error {
	defer b.lock()()
	name = CanonicalName(name)
	if on && !b.Exists(name) {
		return ErrNoMailbox
	}
	return b.setSubscribedLocked(name, on)
}

func (b Mailboxes) setSubscribedLocked(name string, on bool) error {
	subs := b.subscriptions()
	if subs[name] == on {
		return nil
	}
	if on {
		subs[name] = true
	} else {
		delete(subs, name)
	}
	return b.writeSubscriptions(subs)
}

// Init creates the home Maildir, and at the first login the usual folders,
// subscribed: Drafts, Sent, Trash, Junk, Archive
func (b Mailboxes) Init() error {
	defer b.lock()()
	if err := os.MkdirAll(b.Home, 0700); err != nil {
		return err
	}
	if err := initMaildir(b.Home); err != nil {
		return err
	}
	// subscriptions file exists: not the first login, folders may have been
	// deleted on purpose
	if _, err := os.Stat(filepath.Join(b.Home, subscriptionsFile)); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	subs := map[string]bool{Inbox: true}
	for _, name := range defaultFolders {
		if err := b.createLocked(name); err != nil && err != errExists {
			return err
		}
		subs[name] = true
	}
	return b.writeSubscriptions(subs)
}
