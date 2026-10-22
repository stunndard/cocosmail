// Package mailstore keeps the users' mail: Maildir++ folders read and changed
// by the IMAP and POP3 servers, and written to by local delivery.
//
// A user's home is a Maildir (cur/, new/, tmp/): INBOX. Other folders are
// Maildirs in it named "." + folder name, "." separates levels: .Sent,
// .Archive.2024. Flags are in the file names (key:2,FLAGS), like Dovecot does.
//
// Everything in cocosmail goes through this package, which keeps one Folder
// per directory in memory: changes are made under its lock, one at a time,
// and every IMAP session and POP3 session sees them.
package mailstore

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/stunndard/cocosmail/imap/goimap"
)

// files of a folder, next to cur/, new/ and tmp/
const (
	uidListFile  = "cocosmail-uidlist"
	keywordsFile = "dovecot-keywords"
)

// system flags and their letter in file names
var flagLetters = map[imap.Flag]byte{
	imap.FlagDraft:    'D',
	imap.FlagFlagged:  'F',
	imap.FlagAnswered: 'R',
	imap.FlagSeen:     'S',
	imap.FlagDeleted:  'T',
}

var letterFlags = map[byte]imap.Flag{}

func init() {
	for f, l := range flagLetters {
		letterFlags[l] = f
	}
}

// at most 26 keywords per folder, letters a to z, like Dovecot
const maxKeywords = 26

// splitName returns the key and the flags part (after ":2,") of a file name
func splitName(name string) (key, info string) {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		key = name[:i]
		info = name[i+1:]
		if strings.HasPrefix(info, "2,") {
			return key, info[2:]
		}
		// another info version: keep it, no flags
		return key, ""
	}
	return name, ""
}

// fileName returns the name in cur/ of key with flag letters
func fileName(key, letters string) string {
	b := []byte(letters)
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	return key + ":2," + string(b)
}

// lastKey makes keys unique within this process
var lastKey uint64

// newKey returns a new unique message key: time, process and random parts
func newKey() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	host, _ := os.Hostname()
	host = strings.NewReplacer("/", "_", ":", "_", ".", "_").Replace(host)
	now := time.Now()
	return fmt.Sprintf("%d.M%dP%dQ%d%s.%s", now.Unix(), now.Nanosecond()/1000,
		os.Getpid(), atomic.AddUint64(&lastKey, 1), hex.EncodeToString(b), host)
}

// isMaildir tells if dir has a cur directory
func isMaildir(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "cur"))
	return err == nil && fi.IsDir()
}

// initMaildir creates dir with cur, new and tmp
func initMaildir(dir string) error {
	for _, d := range []string{dir, filepath.Join(dir, "cur"), filepath.Join(dir, "new"), filepath.Join(dir, "tmp")} {
		if err := os.Mkdir(d, 0700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

// readKeywords reads the keywords file: "N keyword" per line, N is the letter
// 'a'+N in file names
func readKeywords(dir string) []string {
	f, err := os.Open(filepath.Join(dir, keywordsFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var kw []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.SplitN(s.Text(), " ", 2)
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil || n < 0 || n >= maxKeywords {
			continue
		}
		for len(kw) <= n {
			kw = append(kw, "")
		}
		kw[n] = fields[1]
	}
	return kw
}

func writeKeywords(dir string, kw []string) error {
	var b strings.Builder
	for i, k := range kw {
		if k != "" {
			fmt.Fprintf(&b, "%d %s\n", i, k)
		}
	}
	return writeFileAtomic(filepath.Join(dir, keywordsFile), []byte(b.String()))
}

// writeFileAtomic replaces path with data: never half written
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
