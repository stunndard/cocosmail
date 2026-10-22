package mailstore

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stunndard/cocosmail/imap/goimap"
)

func init() {
	// tests change directories quicker than the mtime check trusts them
	mtimeTrust = time.Hour
}

// deliver writes a message to new/ like local delivery
func deliver(t *testing.T, dir, body string) string {
	t.Helper()
	require.NoError(t, initMaildir(dir))
	key := newKey()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tmp", key), []byte(body), 0600))
	require.NoError(t, os.Rename(filepath.Join(dir, "tmp", key), filepath.Join(dir, "new", key)))
	return key
}

func msg(subject string) string {
	return "From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject + "\r\n\r\nbody of " + subject + "\r\n"
}

func uids(t *testing.T, f *Folder) []imap.UID {
	t.Helper()
	msgs, err := f.Messages()
	require.NoError(t, err)
	var l []imap.UID
	for _, m := range msgs {
		l = append(l, m.UID)
	}
	return l
}

func TestFolderUIDs(t *testing.T) {
	dir := t.TempDir()
	deliver(t, dir, msg("one"))
	deliver(t, dir, msg("two"))

	f, err := Open(dir)
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{1, 2}, uids(t, f))
	validity := f.Validity()
	names, _ := readNames(filepath.Join(dir, "new"))
	assert.Empty(t, names, "moved to cur")

	// delivered while open
	deliver(t, dir, msg("three"))
	Changed(dir)
	assert.Equal(t, []imap.UID{1, 2, 3}, uids(t, f))

	// deleted by someone else
	msgs, _ := f.Messages()
	require.NoError(t, os.Remove(filepath.Join(dir, "cur", msgs[0].name)))
	f.newMtime = time.Time{}
	assert.Equal(t, []imap.UID{2, 3}, uids(t, f))
	f.Close()

	// UIDs and validity kept, also with messages deleted and delivered
	// while nobody had it open
	deliver(t, dir, msg("four"))
	require.NoError(t, os.Remove(filepath.Join(dir, "cur", msgs[1].name)))
	f, err = Open(dir)
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{3, 4}, uids(t, f))
	assert.Equal(t, validity, f.Validity())
	b, err := f.Read(mustMessages(t, f)[0])
	require.NoError(t, err)
	assert.Contains(t, string(b), "Subject: three")
	f.Close()
}

func mustMessages(t *testing.T, f *Folder) []Message {
	msgs, err := f.Messages()
	require.NoError(t, err)
	return msgs
}

func TestFolderFlags(t *testing.T) {
	dir := t.TempDir()
	deliver(t, dir, msg("one"))
	f, err := Open(dir)
	require.NoError(t, err)
	defer f.Close()

	f.mu.Lock()
	m := f.msgs[0]
	changed, err := f.setFlagsLocked(m, []imap.Flag{imap.FlagSeen, "$Forwarded", imap.FlagAnswered, "\\Recent"})
	require.NoError(t, err)
	assert.True(t, changed)
	assert.True(t, strings.HasSuffix(m.name, ":2,RSa"), m.name)
	assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.FlagAnswered, "$Forwarded"}, f.flagsLocked(m))
	changed, _ = f.setFlagsLocked(m, []imap.Flag{imap.FlagAnswered, "$forwarded", imap.FlagSeen})
	assert.False(t, changed, "same flags, keywords in any case")
	f.mu.Unlock()
	assert.Equal(t, []string{"$Forwarded"}, readKeywords(dir))

	// a flag letter of another program is kept
	cur := filepath.Join(dir, "cur")
	require.NoError(t, os.Rename(filepath.Join(cur, m.name), filepath.Join(cur, m.Key+":2,PRSa")))
	f.newMtime = time.Time{}
	require.NoError(t, f.Sync())
	f.mu.Lock()
	_, err = f.setFlagsLocked(f.msgs[0], []imap.Flag{imap.FlagDeleted})
	f.mu.Unlock()
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(f.msgs[0].name, ":2,PT"), f.msgs[0].name)

	// read after a rename by another session
	old := *f.msgs[0]
	require.NoError(t, os.Rename(filepath.Join(cur, old.name), filepath.Join(cur, old.Key+":2,S")))
	f.newMtime = time.Time{}
	require.NoError(t, f.Sync())
	b, err := f.Read(old)
	require.NoError(t, err)
	assert.Contains(t, string(b), "Subject: one")
}

func TestFolderAppendRemove(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, initMaildir(dir))
	f, err := Open(dir)
	require.NoError(t, err)
	date := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	uid, err := f.Append(strings.NewReader(msg("one")), []imap.Flag{imap.FlagSeen}, date)
	require.NoError(t, err)
	assert.Equal(t, imap.UID(1), uid)
	msgs := mustMessages(t, f)
	assert.True(t, msgs[0].Date.Equal(date))
	assert.Equal(t, int64(len(msg("one"))), msgs[0].Size)

	n, err := f.Remove([]imap.UID{1, 7})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	uid, err = f.Append(strings.NewReader(msg("two")), nil, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, imap.UID(2), uid, "UIDs never reused")
	f.Close()

	f, err = Open(dir)
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{2}, uids(t, f))
	f.Close()
}

// the uid list grows by lines, it's rewritten when mostly deleted lines
func TestUIDListCompaction(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, initMaildir(dir))
	f, err := Open(dir)
	require.NoError(t, err)
	defer f.Close()
	for i := 0; i < 150; i++ {
		_, err := f.Append(strings.NewReader(msg(fmt.Sprint(i))), nil, time.Time{})
		require.NoError(t, err)
	}
	lines := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, uidListFile))
		return bytes.Count(b, []byte("\n"))
	}
	assert.Equal(t, 151, lines())
	var del []imap.UID
	for uid := imap.UID(1); uid <= 140; uid++ {
		del = append(del, uid)
	}
	for _, uid := range del[:100] {
		_, err := f.Remove([]imap.UID{uid})
		require.NoError(t, err)
	}
	assert.Equal(t, 251, lines(), "deletions appended")
	_, err = f.Remove(del[100:])
	require.NoError(t, err)
	assert.Equal(t, 11, lines(), "rewritten")

	// read back the same, appended or rewritten
	f2 := &Folder{Path: dir}
	f2.mu.Lock()
	require.NoError(t, f2.syncLocked())
	f2.mu.Unlock()
	assert.Equal(t, uids(t, f), uids(t, f2))
	assert.Equal(t, imap.UID(151), f2.next)
}

// sessions and deliveries at the same time: every message gets one UID
func TestFolderConcurrent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, initMaildir(dir))
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				f, err := Open(dir)
				if !assert.NoError(t, err) {
					return
				}
				if i%2 == 0 {
					_, err = f.Append(strings.NewReader(msg(fmt.Sprint(w, i))), nil, time.Time{})
				} else {
					deliver(t, dir, msg(fmt.Sprint(w, i)))
					Changed(dir)
				}
				assert.NoError(t, err)
				f.Close()
			}
		}(w)
	}
	wg.Wait()
	f, err := Open(dir)
	require.NoError(t, err)
	defer f.Close()
	got := uids(t, f)
	assert.Len(t, got, 100)
	seen := make(map[imap.UID]bool)
	for _, u := range got {
		assert.False(t, seen[u], "duplicate UID %d", u)
		seen[u] = true
	}
}

// unchanged directories are not read again, a delivery is seen
func TestFolderSyncSkipsUnchanged(t *testing.T) {
	mtimeTrust = 0
	defer func() { mtimeTrust = time.Hour }()
	dir := t.TempDir()
	deliver(t, dir, msg("one"))
	f, err := Open(dir)
	require.NoError(t, err)
	defer f.Close()
	// opening moved new/ to cur/: read once more, then nothing changes
	require.NoError(t, f.Sync())
	// a file added to cur/ without changing the recorded mtimes is not seen
	scanned := f.curMtime
	key := newKey()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", key+":2,"), []byte(msg("x")), 0600))
	require.NoError(t, os.Chtimes(filepath.Join(dir, "cur"), scanned, scanned))
	assert.Equal(t, []imap.UID{1}, uids(t, f))

	deliver(t, dir, msg("two"))
	assert.Len(t, uids(t, f), 3)
}

// copying or moving UIDs that don't exist is OK, without COPYUID
func TestCopyNothing(t *testing.T) {
	dir := t.TempDir()
	deliver(t, dir, msg("one"))
	v, _, err := Select(dir, false)
	require.NoError(t, err)
	defer v.Close()
	dest := filepath.Join(dir, ".Trash")
	require.NoError(t, initMaildir(dest))
	f, err := Open(dest)
	require.NoError(t, err)
	defer f.Close()
	var none imap.UIDSet
	none.AddRange(5, 9)
	data, err := v.Copy(none, f)
	require.NoError(t, err)
	assert.Nil(t, data)
	assert.NoError(t, v.Move(nil, none, f))
	assert.Equal(t, []imap.UID{1}, uids(t, v.Folder))
	assert.Empty(t, uids(t, f))
}

// "*" is the last message, also after the last UID was expunged
func TestStarIsLastMessage(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []string{"one", "two", "three"} {
		deliver(t, dir, msg(s))
	}
	v, _, err := Select(dir, false)
	require.NoError(t, err)
	defer v.Close()
	_, err = v.Remove([]imap.UID{3})
	require.NoError(t, err)
	require.NoError(t, v.Sync())
	var got []imap.UID
	var star imap.UIDSet
	star.AddRange(0, 0)
	v.mu.Lock()
	v.forEachLocked(star, func(seq uint32, m *Message) { got = append(got, m.UID) })
	v.mu.Unlock()
	assert.Equal(t, []imap.UID{2}, got)
}
