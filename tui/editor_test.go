package tui

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// memStore keeps settings in memory
type memStore struct {
	values   map[string]string
	saves    []map[string]string
	readOnly map[string]bool
}

func newMemStore() *memStore {
	values := core.SettingsDefaults()
	values["me"] = "mail.example.com"
	values["smtpd_dsns"] = "[::]:25:mail.example.com:nossl:example.com"
	values["pop3d_dsns"] = "[::]:995:mail.example.com:ssl:example.com"
	return &memStore{values: values, readOnly: map[string]bool{}}
}

func (s *memStore) Title() string { return "memory" }
func (s *memStore) Load() (map[string]string, map[string]string, error) {
	sources := make(map[string]string)
	for k := range s.values {
		sources[k] = core.SourceDB
	}
	return copyValues(s.values), sources, nil
}
func (s *memStore) Save(changed map[string]string) error {
	s.saves = append(s.saves, changed)
	for k, v := range changed {
		s.values[k] = v
	}
	return nil
}
func (s *memStore) ReadOnly(key string) string {
	if s.readOnly[key] {
		return "read only in test"
	}
	return ""
}
func (s *memStore) ApplyNote(changed []string) string { return "applied" }

const testW, testH = 100, 30

// setup starts a frame manager on a silent screen, with an editor on store
func setup(t *testing.T, store Store) (*Editor, *vtui.ScreenBuf, *bool) {
	vtui.SetDefaultPalette()
	scr := vtui.NewSilentScreenBuf()
	scr.AllocBuf(testW, testH)
	vtui.FrameManager.Init(scr)
	vtui.FrameManager.KeyBar = vtui.NewKeyBar()
	vtui.FrameManager.KeyBar.SetPosition(0, testH-1, testW-1, testH-1)
	vtui.FrameManager.Push(vtui.NewDesktop())
	ed, err := NewEditor(store, testW, testH)
	if err != nil {
		t.Fatal(err)
	}
	quit := false
	ed.Quit = func() { quit = true }
	vtui.FrameManager.Push(ed)
	return ed, scr, &quit
}

func key(vk uint16) *vtinput.InputEvent {
	return &vtinput.InputEvent{Type: vtinput.KeyEventType, KeyDown: true, VirtualKeyCode: vk}
}

func typeText(s string) (events []*vtinput.InputEvent) {
	for _, r := range s {
		events = append(events, &vtinput.InputEvent{Type: vtinput.KeyEventType, KeyDown: true, Char: r})
	}
	return
}

// run processes events, then returns the screen text
func run(scr *vtui.ScreenBuf, events ...*vtinput.InputEvent) string {
	vtui.FrameManager.InjectEvents(events)
	pr, pw := io.Pipe()
	vtui.FrameManager.PostTask(func() { pw.Close() })
	vtui.FrameManager.Run(vtinput.NewReader(pr, false))
	var b bytes.Buffer
	scr.Dump(&b)
	return b.String()
}

func TestEditorLayout(t *testing.T) {
	ed, _, _ := setup(t, newMemStore())
	// the editor is full screen, not a dialog limited to 80 columns
	rules := vtui.DefaultLayoutRules
	rules.MaxWidth = 0
	vtui.AssertLayoutWithRules(t, ed, rules)
	me, _ := core.SettingByKey("me")
	vtui.AssertLayout(t, ed.editDialog(*me))
	lda, _ := core.SettingByKey("lda_type")
	vtui.AssertLayout(t, ed.editDialog(*lda))
	dsns, _ := core.SettingByKey("smtpd_dsns")
	vtui.AssertLayout(t, ed.editDialog(*dsns))
}

func TestEditorShowsSettings(t *testing.T) {
	store := newMemStore()
	store.values["rest_server_passwd"] = "topsecret"
	_, scr, _ := setup(t, store)
	screen := run(scr)
	for _, want := range []string{"cocosmail settings: memory", "[general]", "me", "mail.example.com", "hide_server_signature", "Hostname of this server", "Save", "Quit"} {
		if !strings.Contains(screen, want) {
			t.Errorf("screen misses %q", want)
		}
	}
	if strings.Contains(screen, "topsecret") {
		t.Error("secret shown")
	}
}

func TestEditorToggleAndSave(t *testing.T) {
	store := newMemStore()
	ed, scr, quit := setup(t, store)
	// row 1 is "me", row 2 hide_server_signature
	screen := run(scr, key(vtinput.VK_DOWN), key(vtinput.VK_RETURN))
	if ed.values["hide_server_signature"] != "true" {
		t.Fatalf("bool not toggled: %q", ed.values["hide_server_signature"])
	}
	if !strings.Contains(screen, "(1 changed)") || !strings.Contains(screen, "changed") {
		t.Error("change not shown")
	}
	// F2, Enter on Save
	run(scr, key(vtinput.VK_F2), key(vtinput.VK_RETURN))
	if len(store.saves) != 1 || store.saves[0]["hide_server_signature"] != "true" || len(store.saves[0]) != 1 {
		t.Fatalf("not saved: %v", store.saves)
	}
	// nothing changed: quit at once
	run(scr, key(vtinput.VK_F10))
	if !*quit {
		t.Error("not quit")
	}
}

func TestEditorEditText(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := []*vtinput.InputEvent{key(vtinput.VK_F4), key(vtinput.VK_END)}
	for range ed.values["me"] {
		events = append(events, key(vtinput.VK_BACK))
	}
	events = append(events, typeText("new.example.com")...)
	events = append(events, key(vtinput.VK_RETURN))
	run(scr, events...)
	if ed.values["me"] != "new.example.com" {
		t.Fatalf("me = %q", ed.values["me"])
	}
}

func TestEditorRejectsInvalid(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	// select smtpd_max_hops with quick search, then edit it
	events := typeText("smtpd_max_h")
	events = append(events, key(vtinput.VK_F4), key(vtinput.VK_END))
	for range ed.values["smtpd_max_hops"] {
		events = append(events, key(vtinput.VK_BACK))
	}
	events = append(events, typeText("many")...)
	events = append(events, key(vtinput.VK_RETURN))
	screen := run(scr, events...)
	if ed.values["smtpd_max_hops"] != "10" {
		t.Fatalf("invalid value accepted: %q", ed.values["smtpd_max_hops"])
	}
	if !strings.Contains(screen, "is not a valid number") {
		t.Error("error not shown")
	}
}

func TestEditorReadOnly(t *testing.T) {
	store := newMemStore()
	store.readOnly["me"] = true
	ed, scr, _ := setup(t, store)
	screen := run(scr, key(vtinput.VK_F4), key(vtinput.VK_F8))
	if ed.values["me"] != "mail.example.com" {
		t.Fatalf("read only setting changed: %q", ed.values["me"])
	}
	if !strings.Contains(screen, "read only in test") {
		t.Error("read only reason not shown")
	}
}

func TestEditorQuitWithChanges(t *testing.T) {
	store := newMemStore()
	_, scr, quit := setup(t, store)
	// change, quit: asked, Cancel keeps editing
	run(scr, key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), key(vtinput.VK_F10), key(vtinput.VK_ESCAPE))
	if *quit {
		t.Fatal("quit without asking")
	}
	// quit, Discard
	run(scr, key(vtinput.VK_F10), key(vtinput.VK_RIGHT), key(vtinput.VK_RETURN))
	if !*quit {
		t.Fatal("not quit after Discard")
	}
	if len(store.saves) != 0 {
		t.Fatal("saved after Discard")
	}
}
