package tui

import (
	"strings"
	"testing"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

func ctrlKey(vk uint16) *vtinput.InputEvent {
	return &vtinput.InputEvent{Type: vtinput.KeyEventType, KeyDown: true, VirtualKeyCode: vk, ControlKeyState: vtinput.LeftCtrlPressed}
}

// openActions edits a setting from all settings, found by quick search
// of its name start
func openActions(name string) []*vtinput.InputEvent {
	events := append([]*vtinput.InputEvent{key(vtinput.VK_TAB)}, toAllSettings()...)
	events = append(events, key(vtinput.VK_TAB))
	events = append(events, typeText(name)...)
	return append(events, key(vtinput.VK_F4))
}

func TestParseActions(t *testing.T) {
	assert := func(got []string, want string) {
		t.Helper()
		if strings.Join(got, ":") != want {
			t.Errorf("got %v, want %s", got, want)
		}
	}
	assert(parseActions("accept:reject:accept", 3), "accept:reject:accept")
	assert(parseActions("reject", 3), "reject:accept:accept")
	assert(parseActions(" reject :drop:reject:reject", 3), "reject:accept:reject")
	assert(parseActions("", 2), "accept:accept")
}

func TestActionsDialogLayout(t *testing.T) {
	ed, _, _ := setup(t, newMemStore())
	for _, name := range []string{"smtpd_spf_action", "smtpd_dkim_action"} {
		s, _ := core.SettingByKey(name)
		vtui.AssertLayout(t, ed.actionsDialog(*s))
	}
	ed.layout(80, 25)
	s, _ := core.SettingByKey("smtpd_dkim_action")
	vtui.AssertLayout(t, ed.actionsDialog(*s))
}

func TestActionsDialogShowsActions(t *testing.T) {
	store := newMemStore()
	store.values["smtpd_dkim_action"] = "accept:accept:reject:accept:accept:accept"
	_, scr, _ := setup(t, store)
	screen := run(scr, openActions("smtpd_dkim_ac")...)
	for _, want := range []string{"COCOSMAIL_SMTPD_DKIM_ACTION", "none", "author", "temperror", "permerror", "reject", "Ctrl+Down"} {
		if !strings.Contains(screen, want) {
			t.Errorf("%q not shown", want)
		}
	}
}

// choose reject for fail, the 4th result, in its list
func TestActionsDialogChoose(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := openActions("smtpd_dkim_ac")
	events = append(events, key(vtinput.VK_TAB), key(vtinput.VK_TAB), key(vtinput.VK_TAB))
	events = append(events, ctrlKey(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_RETURN))
	// Enter presses Ok
	events = append(events, key(vtinput.VK_RETURN))
	run(scr, events...)
	if got := ed.values["smtpd_dkim_action"]; got != "accept:accept:accept:reject:accept:accept" {
		t.Fatalf("smtpd_dkim_action = %q", got)
	}

	// SPF too, and back to accept
	events = openActions("smtpd_spf_ac")
	events = append(events, ctrlKey(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), key(vtinput.VK_RETURN))
	run(scr, events...)
	if got := ed.values["smtpd_spf_action"]; got != "reject:accept:accept:accept:accept:accept" {
		t.Fatalf("smtpd_spf_action = %q", got)
	}
}

// Esc closes it without changes
func TestActionsDialogCancel(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := openActions("smtpd_dkim_ac")
	events = append(events, ctrlKey(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), key(vtinput.VK_ESCAPE))
	run(scr, events...)
	if got := ed.values["smtpd_dkim_action"]; got != core.SettingsDefaults()["smtpd_dkim_action"] {
		t.Fatalf("smtpd_dkim_action = %q", got)
	}
}
