package mailstore

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stunndard/cocosmail/imap/goimap"
	"github.com/stunndard/cocosmail/imap/goimap/imapserver"
)

// ErrExpunged is returned when a message was deleted meanwhile, by another
// session
var ErrExpunged = errors.New("message deleted by another session")

// Message is a message of a folder
type Message struct {
	UID  imap.UID
	Key  string
	Size int64
	// Date is the internal date: when the message was received
	Date time.Time
	// name is the file name in cur/, with the flags
	name string
}

func (m *Message) letters() string {
	_, l := splitName(m.name)
	return l
}

// Folder is a Maildir folder. There is one Folder per directory while it's
// open: all changes are made under its lock, and sent to the IMAP sessions
// which have it selected.
type Folder struct {
	Path string

	// refs counts Open calls not closed yet, protected by foldersMu
	refs int

	mu       sync.Mutex
	loaded   bool
	tracker  *imapserver.MailboxTracker
	validity uint32
	next     imap.UID
	msgs     []*Message // ordered by UID
	keywords []string
	// uids read from the uid list, until the first scan
	known map[string]*Message
	// lines of deleted messages in the uid list, removed when it's rewritten
	dead int
	// directories as of the last scan: no need to scan again if unchanged
	newMtime, curMtime time.Time
}

var (
	foldersMu sync.Mutex
	folders   = make(map[string]*Folder)
)

// Open returns the folder in directory path, which must be a Maildir.
// Close must be called when done.
func Open(path string) (*Folder, error) {
	path = filepath.Clean(path)
	foldersMu.Lock()
	f := folders[path]
	if f == nil {
		f = &Folder{Path: path}
		folders[path] = f
	}
	f.refs++
	foldersMu.Unlock()

	f.mu.Lock()
	err := f.syncLocked()
	f.mu.Unlock()
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Close releases the folder
func (f *Folder) Close() {
	foldersMu.Lock()
	defer foldersMu.Unlock()
	f.refs--
	if f.refs == 0 {
		delete(folders, f.Path)
	}
}

// isOpen tells if a folder in path or under it is open
func isOpen(path string) bool {
	path = filepath.Clean(path)
	foldersMu.Lock()
	defer foldersMu.Unlock()
	for p := range folders {
		if p == path || strings.HasPrefix(p, path+".") {
			return true
		}
	}
	return false
}

// Changed tells that the folder in path may have changed on disk, e.g. a
// message was delivered: sessions which have it selected are told at once.
func Changed(path string) {
	path = filepath.Clean(path)
	foldersMu.Lock()
	f := folders[path]
	if f != nil {
		f.refs++
	}
	foldersMu.Unlock()
	if f == nil {
		return
	}
	defer f.Close()
	f.Sync()
}

// Sync reads changes made on disk: new messages, deleted messages, changed flags
func (f *Folder) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncLocked()
}

// a directory modified recently may change again within the same mtime
var mtimeTrust = 2 * time.Second

// lastValidity makes UIDVALIDITY values unique within this process
var lastValidity uint32

func newValidity() uint32 {
	now := uint32(time.Now().Unix())
	for {
		last := atomic.LoadUint32(&lastValidity)
		v := now
		if v <= last {
			v = last + 1
		}
		if atomic.CompareAndSwapUint32(&lastValidity, last, v) {
			return v
		}
	}
}

// load reads the uid list and the keywords
func (f *Folder) load() error {
	if err := initMaildir(f.Path); err != nil {
		return err
	}
	f.keywords = readKeywords(f.Path)
	f.next = 1
	f.known = make(map[string]*Message)
	file, err := os.Open(filepath.Join(f.Path, uidListFile))
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		f.validity = newValidity()
		return nil
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	if !s.Scan() || !f.parseHeader(s.Text()) {
		// unreadable: new UIDs for everything
		f.validity = newValidity()
		return nil
	}
	byUID := make(map[imap.UID]string)
	for s.Scan() {
		line := s.Text()
		// -UID: deleted
		if strings.HasPrefix(line, "-") {
			if uid, err := strconv.ParseUint(line[1:], 10, 32); err == nil {
				delete(f.known, byUID[imap.UID(uid)])
				f.dead++
			}
			continue
		}
		// UID SIZE DATE KEY
		fields := strings.SplitN(line, " ", 4)
		if len(fields) != 4 {
			continue
		}
		uid, err1 := strconv.ParseUint(fields[0], 10, 32)
		size, err2 := strconv.ParseInt(fields[1], 10, 64)
		date, err3 := strconv.ParseInt(fields[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || uid == 0 {
			continue
		}
		f.known[fields[3]] = &Message{UID: imap.UID(uid), Key: fields[3], Size: size, Date: time.Unix(0, date)}
		byUID[imap.UID(uid)] = fields[3]
		if imap.UID(uid) >= f.next {
			f.next = imap.UID(uid) + 1
		}
	}
	return s.Err()
}

// parseHeader parses "V<validity> N<next uid>"
func (f *Folder) parseHeader(line string) bool {
	var v, n uint32
	if _, err := fmt.Sscanf(line, "V%d N%d", &v, &n); err != nil || v == 0 || n == 0 {
		return false
	}
	f.validity, f.next = v, imap.UID(n)
	return true
}

// The uid list is "V<validity> N<next uid>", then a line per message:
// "UID SIZE DATE KEY". New messages and deletions ("-UID") are appended, so a
// big folder isn't written again for each message: it's rewritten when there
// are more deleted lines than messages.

func (f *Folder) writeUIDList() error {
	f.dead = 0
	var b strings.Builder
	fmt.Fprintf(&b, "V%d N%d\n", f.validity, f.next)
	for _, m := range f.msgs {
		uidLine(&b, m)
	}
	return writeFileAtomic(filepath.Join(f.Path, uidListFile), []byte(b.String()))
}

func uidLine(b *strings.Builder, m *Message) {
	fmt.Fprintf(b, "%d %d %d %s\n", m.UID, m.Size, m.Date.UnixNano(), m.Key)
}

// updateUIDList records added messages and deleted UIDs
func (f *Folder) updateUIDList(added []*Message, deleted []imap.UID) error {
	if f.dead+len(deleted) > len(f.msgs)+100 {
		return f.writeUIDList()
	}
	var b strings.Builder
	for _, uid := range deleted {
		fmt.Fprintf(&b, "-%d\n", uid)
	}
	for _, m := range added {
		uidLine(&b, m)
	}
	file, err := os.OpenFile(filepath.Join(f.Path, uidListFile), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return f.writeUIDList()
	}
	_, err = file.WriteString(b.String())
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	f.dead += len(deleted)
	return err
}

// syncLocked reads the directories if they changed: messages delivered to
// new/ are moved to cur/ and get a UID, deleted ones are expunged, flags
// changed by other programs are read.
func (f *Folder) syncLocked() error {
	if !f.loaded {
		if err := f.load(); err != nil {
			return err
		}
	}
	newDir, curDir := filepath.Join(f.Path, "new"), filepath.Join(f.Path, "cur")
	nfi, err := os.Stat(newDir)
	if err != nil {
		return err
	}
	cfi, err := os.Stat(curDir)
	if err != nil {
		return err
	}
	nm, cm := nfi.ModTime(), cfi.ModTime()
	if f.loaded && nm.Equal(f.newMtime) && cm.Equal(f.curMtime) &&
		time.Since(nm) > mtimeTrust && time.Since(cm) > mtimeTrust {
		return nil
	}
	// mtimes before reading: a change made while reading is seen next time
	f.newMtime, f.curMtime = nm, cm

	// new/ to cur/, keeping flags if a program set some
	names, err := readNames(newDir)
	if err != nil {
		return err
	}
	for _, name := range names {
		key, letters := splitName(name)
		if key == "" {
			continue
		}
		err := os.Rename(filepath.Join(newDir, name), filepath.Join(curDir, fileName(key, letters)))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	names, err = readNames(curDir)
	if err != nil {
		return err
	}
	onDisk := make(map[string]string, len(names))
	for _, name := range names {
		if key, _ := splitName(name); key != "" {
			onDisk[key] = name
		}
	}

	var (
		kept     []*Message
		expunged []uint32
		gone     []imap.UID
		flagged  []*Message
	)
	for i, m := range f.msgs {
		name, ok := onDisk[m.Key]
		if !ok {
			expunged = append(expunged, uint32(i+1))
			gone = append(gone, m.UID)
			continue
		}
		delete(onDisk, m.Key)
		if name != m.name {
			m.name = name
			flagged = append(flagged, m)
		}
		kept = append(kept, m)
	}

	// messages not known yet: UID from the uid list, or a new one in the
	// order they arrived
	var added []*Message
	for key, name := range onDisk {
		if m := f.known[key]; m != nil {
			m.name = name
			added = append(added, m)
			delete(f.known, key)
			continue
		}
		fi, err := os.Stat(filepath.Join(curDir, name))
		if err != nil {
			continue
		}
		added = append(added, &Message{Key: key, name: name, Size: fi.Size(), Date: fi.ModTime()})
	}
	sort.Slice(added, func(i, j int) bool {
		a, b := added[i], added[j]
		if (a.UID == 0) != (b.UID == 0) {
			return a.UID != 0
		}
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		if !a.Date.Equal(b.Date) {
			return a.Date.Before(b.Date)
		}
		return a.Key < b.Key
	})
	firstNew := f.next
	for _, m := range added {
		if m.UID == 0 {
			m.UID = f.next
			f.next++
		}
	}
	// in the uid list, deleted while nobody had the folder open
	var stale []imap.UID
	for _, m := range f.known {
		stale = append(stale, m.UID)
	}
	f.known = nil

	if !f.loaded {
		// first scan: everything is new to the sessions
		f.msgs = append(kept, added...)
		sort.Slice(f.msgs, func(i, j int) bool { return f.msgs[i].UID < f.msgs[j].UID })
		f.tracker = imapserver.NewMailboxTracker(uint32(len(f.msgs)))
		f.loaded = true
		var fresh []*Message
		for _, m := range added {
			if m.UID >= firstNew {
				fresh = append(fresh, m)
			}
		}
		if fresh == nil && stale == nil && !uidListMissing(f.Path) {
			return nil
		}
		return f.updateUIDList(fresh, stale)
	}

	// tell the sessions: expunged from the end, so numbers stay right
	for i := len(expunged) - 1; i >= 0; i-- {
		f.tracker.QueueExpunge(expunged[i])
	}
	f.msgs = kept
	seq := make(map[*Message]uint32, len(f.msgs))
	for i, m := range f.msgs {
		seq[m] = uint32(i + 1)
	}
	for _, m := range flagged {
		f.tracker.QueueMessageFlags(seq[m], m.UID, f.flagsLocked(m), nil)
	}
	for _, m := range added {
		f.msgs = append(f.msgs, m)
		f.tracker.QueueNumMessages(uint32(len(f.msgs)))
	}
	if len(gone) > 0 || len(added) > 0 {
		return f.updateUIDList(added, gone)
	}
	return nil
}

func uidListMissing(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, uidListFile))
	return err != nil
}

// readNames returns the file names in dir, without dot files
func readNames(dir string) ([]string, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	out := names[:0]
	for _, n := range names {
		if n != "" && n[0] != '.' {
			out = append(out, n)
		}
	}
	return out, nil
}

// flagsLocked returns the flags of m
func (f *Folder) flagsLocked(m *Message) []imap.Flag {
	flags := []imap.Flag{}
	for _, l := range []byte(m.letters()) {
		if flag, ok := letterFlags[l]; ok {
			flags = append(flags, flag)
		} else if l >= 'a' && l <= 'z' && int(l-'a') < len(f.keywords) && f.keywords[l-'a'] != "" {
			flags = append(flags, imap.Flag(f.keywords[l-'a']))
		}
	}
	return flags
}

func hasFlag(flags []imap.Flag, flag imap.Flag) bool {
	for _, f := range flags {
		if strings.EqualFold(string(f), string(flag)) {
			return true
		}
	}
	return false
}

// lettersLocked returns the file name letters for flags. keep are letters of
// the current name kept as they are (flags of other programs). New keywords
// get a letter while there are free ones, others are not stored.
func (f *Folder) lettersLocked(flags []imap.Flag, keep string) string {
	var b []byte
	for _, l := range []byte(keep) {
		if _, ok := letterFlags[l]; !ok && !(l >= 'a' && l <= 'z') {
			b = append(b, l)
		}
	}
	seen := make(map[byte]bool)
	for _, flag := range flags {
		l, ok := f.letterLocked(flag)
		if ok && !seen[l] {
			seen[l] = true
			b = append(b, l)
		}
	}
	return string(b)
}

func (f *Folder) letterLocked(flag imap.Flag) (byte, bool) {
	for sys, l := range flagLetters {
		if strings.EqualFold(string(flag), string(sys)) {
			return l, true
		}
	}
	if strings.HasPrefix(string(flag), "\\") {
		// \Recent and unknown system flags are not stored
		return 0, false
	}
	free := -1
	for i, k := range f.keywords {
		if strings.EqualFold(k, string(flag)) {
			return 'a' + byte(i), true
		}
		if k == "" && free < 0 {
			free = i
		}
	}
	if free < 0 {
		if len(f.keywords) >= maxKeywords {
			return 0, false
		}
		free = len(f.keywords)
		f.keywords = append(f.keywords, "")
	}
	f.keywords[free] = string(flag)
	if err := writeKeywords(f.Path, f.keywords); err != nil {
		f.keywords[free] = ""
		return 0, false
	}
	if f.tracker != nil {
		f.tracker.QueueMailboxFlags(f.mailboxFlagsLocked())
	}
	return 'a' + byte(free), true
}

// mailboxFlagsLocked returns the flags messages can have: system flags and
// the keywords in use
func (f *Folder) mailboxFlagsLocked() []imap.Flag {
	flags := []imap.Flag{imap.FlagAnswered, imap.FlagDeleted, imap.FlagDraft, imap.FlagFlagged, imap.FlagSeen}
	for _, k := range f.keywords {
		if k != "" {
			flags = append(flags, imap.Flag(k))
		}
	}
	return flags
}

// setFlagsLocked renames the file of m to have flags. It returns false if
// nothing changed.
func (f *Folder) setFlagsLocked(m *Message, flags []imap.Flag) (bool, error) {
	name := fileName(m.Key, f.lettersLocked(flags, m.letters()))
	if name == m.name {
		return false, nil
	}
	cur := filepath.Join(f.Path, "cur")
	if err := os.Rename(filepath.Join(cur, m.name), filepath.Join(cur, name)); err != nil {
		if os.IsNotExist(err) {
			return false, ErrExpunged
		}
		return false, err
	}
	m.name = name
	return true, nil
}

// Append adds a message read from r, with flags and date (now if zero)
func (f *Folder) Append(r io.Reader, flags []imap.Flag, date time.Time) (imap.UID, error) {
	key := newKey()
	tmp := filepath.Join(f.Path, "tmp", key)
	w, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	size, err := io.Copy(w, r)
	if err == nil {
		err = w.Sync()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil && !date.IsZero() {
		err = os.Chtimes(tmp, date, date)
	}
	var fi os.FileInfo
	if err == nil {
		fi, err = os.Stat(tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	name := fileName(key, f.lettersLocked(flags, ""))
	if err := os.Rename(tmp, filepath.Join(f.Path, "cur", name)); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	m := &Message{UID: f.next, Key: key, name: name, Size: size, Date: fi.ModTime()}
	f.next++
	f.msgs = append(f.msgs, m)
	f.tracker.QueueNumMessages(uint32(len(f.msgs)))
	return m.UID, f.updateUIDList([]*Message{m}, nil)
}

// expungeLocked deletes the messages for which del returns true
func (f *Folder) expungeLocked(del func(*Message) bool) (removed int, err error) {
	var (
		kept     []*Message
		expunged []uint32
		gone     []imap.UID
	)
	for i, m := range f.msgs {
		if !del(m) {
			kept = append(kept, m)
			continue
		}
		if e := os.Remove(filepath.Join(f.Path, "cur", m.name)); e != nil && !os.IsNotExist(e) {
			err = e
			kept = append(kept, m)
			continue
		}
		expunged = append(expunged, uint32(i+1))
		gone = append(gone, m.UID)
	}
	if len(expunged) == 0 {
		return 0, err
	}
	for i := len(expunged) - 1; i >= 0; i-- {
		f.tracker.QueueExpunge(expunged[i])
	}
	f.msgs = kept
	if e := f.updateUIDList(nil, gone); err == nil {
		err = e
	}
	return len(expunged), err
}

// read returns the content of m. The file is renamed when flags change:
// if it moved, it's read again with the lock held.
func (f *Folder) read(m Message) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(f.Path, "cur", m.name))
	if err == nil || !os.IsNotExist(err) {
		return b, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cur := range f.msgs {
		if cur.UID == m.UID {
			return os.ReadFile(filepath.Join(f.Path, "cur", cur.name))
		}
	}
	return nil, ErrExpunged
}

// Messages returns the messages of the folder, as of now
func (f *Folder) Messages() ([]Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.syncLocked(); err != nil {
		return nil, err
	}
	l := make([]Message, len(f.msgs))
	for i, m := range f.msgs {
		l[i] = *m
	}
	return l, nil
}

// Read returns the content of message m, from Messages
func (f *Folder) Read(m Message) ([]byte, error) {
	return f.read(m)
}

// Remove deletes the messages with these UIDs. Those already deleted are
// ignored. It returns how many were deleted.
func (f *Folder) Remove(uids []imap.UID) (int, error) {
	set := make(map[imap.UID]bool, len(uids))
	for _, u := range uids {
		set[u] = true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.syncLocked(); err != nil {
		return 0, err
	}
	return f.expungeLocked(func(m *Message) bool { return set[m.UID] })
}

// Validity returns the UIDVALIDITY of the folder
func (f *Folder) Validity() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validity
}

// Status returns the STATUS data of the folder
func (f *Folder) Status(options *imap.StatusOptions) *imap.StatusData {
	f.mu.Lock()
	defer f.mu.Unlock()
	data := &imap.StatusData{}
	if options.NumMessages {
		n := uint32(len(f.msgs))
		data.NumMessages = &n
	}
	if options.UIDNext {
		data.UIDNext = f.next
	}
	if options.UIDValidity {
		data.UIDValidity = f.validity
	}
	if options.NumUnseen {
		n := uint32(len(f.msgs)) - f.countLocked('S')
		data.NumUnseen = &n
	}
	if options.NumDeleted {
		n := f.countLocked('T')
		data.NumDeleted = &n
	}
	if options.Size {
		var size int64
		for _, m := range f.msgs {
			size += m.Size
		}
		data.Size = &size
	}
	if options.NumRecent {
		n := uint32(0)
		data.NumRecent = &n
	}
	return data
}

func (f *Folder) countLocked(letter byte) uint32 {
	var n uint32
	for _, m := range f.msgs {
		if strings.IndexByte(m.letters(), letter) >= 0 {
			n++
		}
	}
	return n
}
