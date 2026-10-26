package mailstore

import (
	"bufio"
	"bytes"
	"strings"
	"time"

	"github.com/emersion/go-message/textproto"
	"github.com/stunndard/cocosmail/imap/goimap"
	"github.com/stunndard/cocosmail/imap/goimap/imapserver"
)

// View is a folder selected by an IMAP session: each session has its own
// message numbers and its own queue of changes to tell.
// Based on imapmemserver of go-imap (MIT license).
type View struct {
	*Folder
	ReadOnly  bool
	tracker   *imapserver.SessionTracker
	searchRes imap.UIDSet
}

// how often an idle session looks for changes made by other programs, changes
// made by cocosmail are told at once
var idleSyncInterval = 15 * time.Second

// Select opens the folder in path for an IMAP session
func Select(path string, readOnly bool) (*View, *imap.SelectData, error) {
	f, err := Open(path)
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &View{Folder: f, ReadOnly: readOnly, tracker: f.tracker.NewSession()}

	flags := f.mailboxFlagsLocked()
	permanent := []imap.Flag{}
	if !readOnly {
		permanent = append(permanent, flags...)
		if len(f.keywords) < maxKeywords || hasFree(f.keywords) {
			permanent = append(permanent, imap.FlagWildcard)
		}
	}
	var firstUnseen uint32
	for i, m := range f.msgs {
		if strings.IndexByte(m.letters(), 'S') < 0 {
			firstUnseen = uint32(i + 1)
			break
		}
	}
	return v, &imap.SelectData{
		Flags:             flags,
		PermanentFlags:    permanent,
		NumMessages:       uint32(len(f.msgs)),
		FirstUnseenSeqNum: firstUnseen,
		UIDNext:           f.next,
		UIDValidity:       f.validity,
	}, nil
}

func hasFree(keywords []string) bool {
	for _, k := range keywords {
		if k == "" {
			return true
		}
	}
	return false
}

// Close unselects the folder
func (v *View) Close() {
	v.tracker.Close()
	v.Folder.Close()
}

// Poll tells the session about changes
func (v *View) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if err := v.Sync(); err != nil {
		return err
	}
	return v.tracker.Poll(w, allowExpunge)
}

// Idle tells the session about changes as they happen, until stop is closed
func (v *View) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(idleSyncInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				_ = v.Sync()
			}
		}
	}()
	return v.tracker.Idle(w, stop)
}

// item is a message as of a command, used without the lock
type item struct {
	seq   uint32 // as the session knows it
	msg   Message
	flags []imap.Flag
}

// itemsLocked returns the messages of numSet the session knows about
func (v *View) itemsLocked(numSet imap.NumSet, f func(seq uint32, m *Message)) []item {
	var items []item
	v.forEachLocked(numSet, func(seq uint32, m *Message) {
		if f != nil {
			f(seq, m)
		}
		if s := v.tracker.EncodeSeqNum(seq); s != 0 {
			items = append(items, item{seq: s, msg: *m, flags: v.flagsLocked(m)})
		}
	})
	return items
}

// Fetch writes the FETCH responses. Reading a body section without PEEK sets
// \Seen.
func (v *View) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	markSeen := false
	if !v.ReadOnly {
		for _, bs := range options.BodySection {
			if !bs.Peek {
				markSeen = true
			}
		}
	}
	seen := make(map[imap.UID]bool)
	v.mu.Lock()
	items := v.itemsLocked(numSet, func(seq uint32, m *Message) {
		if !markSeen {
			return
		}
		flags := v.flagsLocked(m)
		if hasFlag(flags, imap.FlagSeen) {
			return
		}
		if changed, err := v.setFlagsLocked(m, append(flags, imap.FlagSeen)); changed && err == nil {
			v.Folder.tracker.QueueMessageFlags(seq, m.UID, v.flagsLocked(m), v.tracker)
			seen[m.UID] = true
		}
	})
	v.mu.Unlock()

	for _, it := range items {
		if err := v.fetch(w, it, options, seen[it.msg.UID]); err != nil {
			return err
		}
	}
	return nil
}

func needsContent(o *imap.FetchOptions) bool {
	return o.Envelope || o.BodyStructure != nil || len(o.BodySection) > 0 ||
		len(o.BinarySection) > 0 || len(o.BinarySectionSize) > 0
}

func (v *View) fetch(w *imapserver.FetchWriter, it item, options *imap.FetchOptions, flagsChanged bool) error {
	var buf []byte
	if needsContent(options) {
		var err error
		if buf, err = v.read(it.msg); err == ErrExpunged {
			return nil
		} else if err != nil {
			return err
		}
	}
	rw := w.CreateMessage(it.seq)
	rw.WriteUID(it.msg.UID)
	if options.Flags || flagsChanged {
		rw.WriteFlags(it.flags)
	}
	if options.InternalDate {
		rw.WriteInternalDate(it.msg.Date)
	}
	if options.RFC822Size {
		rw.WriteRFC822Size(it.msg.Size)
	}
	if options.Envelope {
		rw.WriteEnvelope(envelope(buf))
	}
	if options.BodyStructure != nil {
		rw.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(buf)))
	}
	for _, bs := range options.BodySection {
		b := imapserver.ExtractBodySection(bytes.NewReader(buf), bs)
		wc := rw.WriteBodySection(bs, int64(len(b)))
		_, err := wc.Write(b)
		if cerr := wc.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	for _, bs := range options.BinarySection {
		b := imapserver.ExtractBinarySection(bytes.NewReader(buf), bs)
		wc := rw.WriteBinarySection(bs, int64(len(b)))
		_, err := wc.Write(b)
		if cerr := wc.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	for _, bss := range options.BinarySectionSize {
		rw.WriteBinarySectionSize(bss, imapserver.ExtractBinarySectionSize(bytes.NewReader(buf), bss))
	}
	return rw.Close()
}

func envelope(buf []byte) *imap.Envelope {
	header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		return nil
	}
	return imapserver.ExtractEnvelope(header)
}

var errReadOnly = &imap.Error{
	Type: imap.StatusResponseTypeNo,
	Text: "Mailbox is read-only",
}

// Store changes flags
func (v *View) Store(w *imapserver.FetchWriter, numSet imap.NumSet, store *imap.StoreFlags, options *imap.StoreOptions) error {
	if v.ReadOnly {
		return errReadOnly
	}
	var err error
	v.mu.Lock()
	items := v.itemsLocked(numSet, func(seq uint32, m *Message) {
		changed, e := v.setFlagsLocked(m, storeFlags(v.flagsLocked(m), store))
		if e != nil && e != ErrExpunged && err == nil {
			err = e
		}
		if changed {
			v.Folder.tracker.QueueMessageFlags(seq, m.UID, v.flagsLocked(m), v.tracker)
		}
	})
	v.mu.Unlock()
	if err != nil {
		return err
	}
	if store.Silent {
		return nil
	}
	for _, it := range items {
		rw := w.CreateMessage(it.seq)
		rw.WriteUID(it.msg.UID)
		rw.WriteFlags(it.flags)
		if err := rw.Close(); err != nil {
			return err
		}
	}
	return nil
}

func storeFlags(cur []imap.Flag, store *imap.StoreFlags) []imap.Flag {
	switch store.Op {
	case imap.StoreFlagsSet:
		return store.Flags
	case imap.StoreFlagsAdd:
		return append(cur, store.Flags...)
	}
	var out []imap.Flag
	for _, f := range cur {
		if !hasFlag(store.Flags, f) {
			out = append(out, f)
		}
	}
	return out
}

// Expunge deletes the messages flagged \Deleted, only those in uids if not nil
func (v *View) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if v.ReadOnly {
		return errReadOnly
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.expungeLocked(func(m *Message) bool {
		return (uids == nil || uids.Contains(m.UID)) && strings.IndexByte(m.letters(), 'T') >= 0
	})
	return err
}

// Copy copies messages to dest. It returns the UIDs in both folders, nil when
// no message matched.
func (v *View) Copy(numSet imap.NumSet, dest *Folder) (*imap.CopyData, error) {
	if dest == v.Folder {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Source and destination mailboxes are identical"}
	}
	v.mu.Lock()
	items := v.itemsLocked(numSet, nil)
	v.mu.Unlock()

	data := &imap.CopyData{}
	for _, it := range items {
		b, err := v.read(it.msg)
		if err == ErrExpunged {
			continue
		} else if err != nil {
			return nil, err
		}
		uid, err := dest.Append(bytes.NewReader(b), it.flags, it.msg.Date)
		if err != nil {
			return nil, err
		}
		data.SourceUIDs.AddNum(it.msg.UID)
		data.DestUIDs.AddNum(uid)
	}
	if len(data.SourceUIDs) == 0 {
		// nothing copied: OK without COPYUID, it can't have empty sets
		return nil, nil
	}
	dest.mu.Lock()
	data.UIDValidity = dest.validity
	dest.mu.Unlock()
	return data, nil
}

// Move moves messages to dest. The expunges are told by the next Poll.
func (v *View) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest *Folder) error {
	if v.ReadOnly {
		return errReadOnly
	}
	data, err := v.Copy(numSet, dest)
	if err != nil || data == nil {
		return err
	}
	if err := w.WriteCopyData(data); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err = v.expungeLocked(func(m *Message) bool { return data.SourceUIDs.Contains(m.UID) })
	return err
}

// Search returns the messages matching criteria
func (v *View) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	type candidate struct {
		seq   uint32
		msg   Message
		flags []imap.Flag
	}
	v.mu.Lock()
	v.staticSearchCriteria(criteria)
	list := make([]candidate, len(v.msgs))
	for i, m := range v.msgs {
		list[i] = candidate{v.tracker.EncodeSeqNum(uint32(i + 1)), *m, v.flagsLocked(m)}
	}
	v.mu.Unlock()

	var (
		data   imap.SearchData
		seqSet imap.SeqSet
		uidSet imap.UIDSet
	)
	for _, c := range list {
		s := &searched{folder: v.Folder, msg: c.msg, flags: c.flags}
		if !s.match(c.seq, criteria) {
			continue
		}
		uidSet.AddNum(c.msg.UID)
		var num uint32
		switch kind {
		case imapserver.NumKindSeq:
			if c.seq == 0 {
				continue
			}
			seqSet.AddNum(c.seq)
			num = c.seq
		case imapserver.NumKindUID:
			num = uint32(c.msg.UID)
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if num > data.Max {
			data.Max = num
		}
		data.Count++
	}
	if kind == imapserver.NumKindSeq {
		data.All = seqSet
	} else {
		data.All = uidSet
	}
	if options.ReturnSave {
		v.searchRes = uidSet
	}
	return &data, nil
}

func (v *View) staticSearchCriteria(criteria *imap.SearchCriteria) {
	seqNums := make([]imap.SeqSet, 0, len(criteria.SeqNum))
	for _, seqSet := range criteria.SeqNum {
		switch numSet := v.staticNumSet(seqSet).(type) {
		case imap.SeqSet:
			seqNums = append(seqNums, numSet)
		case imap.UIDSet: // SEARCHRES
			criteria.UID = append(criteria.UID, numSet)
		}
	}
	criteria.SeqNum = seqNums
	for i, uidSet := range criteria.UID {
		criteria.UID[i] = v.staticNumSet(uidSet).(imap.UIDSet)
	}
	for i := range criteria.Not {
		v.staticSearchCriteria(&criteria.Not[i])
	}
	for i := range criteria.Or {
		for j := range criteria.Or[i] {
			v.staticSearchCriteria(&criteria.Or[i][j])
		}
	}
}

func (v *View) forEachLocked(numSet imap.NumSet, f func(seq uint32, m *Message)) {
	numSet = v.staticNumSet(numSet)
	for i, m := range v.msgs {
		seq := uint32(i + 1)
		var contains bool
		switch numSet := numSet.(type) {
		case imap.SeqSet:
			s := v.tracker.EncodeSeqNum(seq)
			contains = s != 0 && numSet.Contains(s)
		case imap.UIDSet:
			contains = numSet.Contains(m.UID)
		}
		if contains {
			f(seq, m)
		}
	}
}

// staticNumSet replaces "*" with the last message, and "$" with the result of
// the last SEARCH
func (v *View) staticNumSet(numSet imap.NumSet) imap.NumSet {
	if imap.IsSearchRes(numSet) {
		return v.searchRes
	}
	switch numSet := numSet.(type) {
	case imap.SeqSet:
		// the last message the client knows of
		var max uint32
		for i := len(v.msgs); i > 0 && max == 0; i-- {
			max = v.tracker.EncodeSeqNum(uint32(i))
		}
		for i := range numSet {
			r := &numSet[i]
			staticNumRange(&r.Start, &r.Stop, max)
		}
	case imap.UIDSet:
		// the UID of the last message, not the last one given: it may be
		// expunged (RFC 9051 6.4.9). 0 matches nothing in an empty folder.
		var max uint32
		if len(v.msgs) > 0 {
			max = uint32(v.msgs[len(v.msgs)-1].UID)
		}
		for i := range numSet {
			r := &numSet[i]
			staticNumRange((*uint32)(&r.Start), (*uint32)(&r.Stop), max)
		}
	}
	return numSet
}

func staticNumRange(start, stop *uint32, max uint32) {
	dyn := false
	if *start == 0 {
		*start = max
		dyn = true
	}
	if *stop == 0 {
		*stop = max
		dyn = true
	}
	if dyn && *start > *stop {
		*start, *stop = *stop, *start
	}
}
