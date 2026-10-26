package mailstore

import (
	"bytes"
	"io"
	"strings"
	"time"

	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/stunndard/cocosmail/imap/goimap"
)

// searched is a message being matched against SEARCH criteria: its content
// is read only if a criterion needs it.
// Based on imapmemserver of go-imap (MIT license).
type searched struct {
	folder *Folder
	msg    Message
	flags  []imap.Flag
	buf    []byte
	read   bool
}

func (s *searched) content() []byte {
	if !s.read {
		s.read = true
		s.buf, _ = s.folder.read(s.msg)
	}
	return s.buf
}

func (s *searched) entity() *gomessage.Entity {
	e, _ := gomessage.Read(bytes.NewReader(s.content()))
	if e == nil {
		e, _ = gomessage.New(gomessage.Header{}, bytes.NewReader(nil))
	}
	return e
}

func (s *searched) match(seq uint32, criteria *imap.SearchCriteria) bool {
	for _, seqSet := range criteria.SeqNum {
		if seq == 0 || !seqSet.Contains(seq) {
			return false
		}
	}
	for _, uidSet := range criteria.UID {
		if !uidSet.Contains(s.msg.UID) {
			return false
		}
	}
	if !matchDate(s.msg.Date, criteria.Since, criteria.Before) {
		return false
	}
	for _, flag := range criteria.Flag {
		if !hasFlag(s.flags, flag) {
			return false
		}
	}
	for _, flag := range criteria.NotFlag {
		if hasFlag(s.flags, flag) {
			return false
		}
	}
	if criteria.Larger != 0 && s.msg.Size <= criteria.Larger {
		return false
	}
	if criteria.Smaller != 0 && s.msg.Size >= criteria.Smaller {
		return false
	}

	if len(criteria.Header) > 0 || !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() {
		header := mail.Header{Header: s.entity().Header}
		for _, fc := range criteria.Header {
			if !matchHeaderFields(header.FieldsByKey(fc.Key), fc.Value) {
				return false
			}
		}
		if !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() {
			t, err := header.Date()
			if err != nil || !matchDate(t, criteria.SentSince, criteria.SentBefore) {
				return false
			}
		}
	}
	for _, text := range criteria.Text {
		if !matchEntity(s.entity(), text, true) {
			return false
		}
	}
	for _, body := range criteria.Body {
		if !matchEntity(s.entity(), body, false) {
			return false
		}
	}
	for _, not := range criteria.Not {
		if s.match(seq, &not) {
			return false
		}
	}
	for _, or := range criteria.Or {
		if !s.match(seq, &or[0]) && !s.match(seq, &or[1]) {
			return false
		}
	}
	return true
}

func matchDate(t, since, before time.Time) bool {
	// RFC 3501: dates are compared without time zone
	t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if !since.IsZero() && t.Before(since) {
		return false
	}
	if !before.IsZero() && !t.Before(before) {
		return false
	}
	return true
}

func matchHeaderFields(fields gomessage.HeaderFields, pattern string) bool {
	if pattern == "" {
		return fields.Len() > 0
	}
	pattern = strings.ToLower(pattern)
	for fields.Next() {
		v, _ := fields.Text()
		if strings.Contains(strings.ToLower(v), pattern) {
			return true
		}
	}
	return false
}

func matchEntity(e *gomessage.Entity, pattern string, includeHeader bool) bool {
	if pattern == "" {
		return true
	}
	if includeHeader && matchHeaderFields(e.Header.Fields(), pattern) {
		return true
	}
	if mr := e.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return false
			} else if err != nil {
				return false
			}
			if matchEntity(part, pattern, includeHeader) {
				return true
			}
		}
	}
	t, _, err := e.Header.ContentType()
	if err != nil {
		return false
	}
	if !strings.HasPrefix(t, "text/") && !strings.HasPrefix(t, "message/") {
		return false
	}
	buf, err := io.ReadAll(e.Body)
	if err != nil {
		return false
	}
	return bytes.Contains(bytes.ToLower(buf), bytes.ToLower([]byte(pattern)))
}
