package tui

import (
	"strings"
	"testing"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// openDsnEditor selects smtpd_dsns in the smtpd section and opens its editor
func openDsnEditor() []*vtinput.InputEvent {
	return []*vtinput.InputEvent{
		key(vtinput.VK_TAB), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN),
		key(vtinput.VK_RETURN),                       // smtpd section, focus to settings: smtpd_launch
		key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), // smtpd_dsns
	}
}

func TestDsnEditorLayout(t *testing.T) {
	ed, _, _ := setup(t, newMemStore())
	de := newDsnEditor(ed, "smtpd_dsns")
	vtui.AssertLayout(t, de.rowDialog(de.newDsn(), true, func(core.DsnFields) {}))
	rules := vtui.DefaultLayoutRules
	rules.MaxWidth = 0
	vtui.AssertLayoutWithRules(t, de, rules)
	ed.layout(80, 25)
	de = newDsnEditor(ed, "pop3d_dsns")
	vtui.AssertLayoutWithRules(t, de, rules)
	vtui.AssertLayout(t, de.rowDialog(de.newDsn(), true, func(core.DsnFields) {}))
}

func TestDsnEditorShowsListeners(t *testing.T) {
	store := newMemStore()
	store.values["smtpd_dsns"] = "[::]:25:mail.example.com:nossl:example.com;192.0.2.10:465:smtp.example.com:ssl:smtp"
	_, scr, _ := setup(t, store)
	screen := run(scr, openDsnEditor()...)
	for _, want := range []string{"COCOSMAIL_SMTPD_DSNS", "IP address", "Certificate", ":: (all)", "192.0.2.10", "465", "smtp.example.com", "ssl", "7New", "8Delete", "2Apply", "10Close"} {
		if !strings.Contains(screen, want) {
			t.Errorf("screen misses %q", want)
		}
	}
}

func TestDsnEditorAddDeleteApply(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := openDsnEditor()
	// new listener: IP 192.0.2.10, defaults for the rest (port 25, me, nossl)
	events = append(events, key(vtinput.VK_F7))
	events = append(events, typeText("192.0.2.10")...)
	events = append(events, key(vtinput.VK_RETURN))
	// delete the first one, the original [::]:25
	events = append(events, key(vtinput.VK_HOME), key(vtinput.VK_F8), key(vtinput.VK_RETURN))
	// apply
	events = append(events, key(vtinput.VK_F2))
	run(scr, events...)
	if got := ed.values["smtpd_dsns"]; got != "192.0.2.10:25:mail.example.com:nossl:mail.example.com" {
		t.Fatalf("smtpd_dsns = %q", got)
	}
}

func TestDsnEditorRejectsInvalid(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := openDsnEditor()
	events = append(events, key(vtinput.VK_F7))
	events = append(events, typeText("not-an-ip")...)
	events = append(events, key(vtinput.VK_RETURN))
	screen := run(scr, events...)
	if !strings.Contains(screen, "is not an IP address") {
		t.Error("error not shown")
	}
	if ed.values["smtpd_dsns"] != store.values["smtpd_dsns"] {
		t.Error("value changed")
	}
}

func TestDsnEditorPop3Clear(t *testing.T) {
	store := newMemStore()
	ed, _, _ := setup(t, store)
	de := newDsnEditor(ed, "pop3d_dsns")
	if err := de.checkDsn(core.DsnFields{IP: "192.0.2.1", Port: "110", Hostname: "h", SSL: "nossl", Cert: "c"}); err == nil {
		t.Error("POP3 in clear text on a public address accepted")
	}
	if err := de.checkDsn(core.DsnFields{IP: "::1", Port: "110", Hostname: "h", SSL: "nossl", Cert: "c"}); err != nil {
		t.Errorf("POP3 in clear text on loopback refused: %v", err)
	}
}

func TestDsnEditorCancel(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := openDsnEditor()
	events = append(events, key(vtinput.VK_F8), key(vtinput.VK_RETURN)) // delete the only listener
	events = append(events, key(vtinput.VK_F10))                        // asks: Apply, Discard, Cancel
	screen := run(scr, events...)
	if !strings.Contains(screen, "The listeners were changed") {
		t.Error("cancel didn't ask")
	}
	run(scr, key(vtinput.VK_RIGHT), key(vtinput.VK_RETURN)) // Discard
	if ed.values["smtpd_dsns"] != store.values["smtpd_dsns"] {
		t.Error("discarded changes applied")
	}
}
