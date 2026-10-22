package tui

import (
	"strings"
	"testing"

	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

func TestParseLocalIps(t *testing.T) {
	for _, v := range []string{
		"0.0.0.0&::",
		"192.0.2.1:mail.example.com|[2001:db8::1]:mail.example.com|::",
		"127.0.0.1",
	} {
		ips, rr := parseLocalIps(v)
		sep := "&"
		if rr {
			sep = "|"
		}
		parts := make([]string, len(ips))
		for i, ip := range ips {
			parts[i] = ip.String()
		}
		if got := strings.Join(parts, sep); got != v {
			t.Errorf("%q -> %q", v, got)
		}
	}
}

// openLocalIpsEditor selects deliverd_local_ips in the deliverd section and opens its editor
func openLocalIpsEditor() []*vtinput.InputEvent {
	return []*vtinput.InputEvent{
		key(vtinput.VK_TAB), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN),
		key(vtinput.VK_RETURN),                       // deliverd section: deliverd_launch
		key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), // deliverd_local_ips
	}
}

func TestLocalIpsEditorLayout(t *testing.T) {
	ed, _, _ := setup(t, newMemStore())
	le := newLocalIpsEditor(ed)
	rules := vtui.DefaultLayoutRules
	rules.MaxWidth = 0
	vtui.AssertLayoutWithRules(t, le, rules)
	vtui.AssertLayout(t, le.rowDialog(localIP{IP: "0.0.0.0"}, true, func(localIP) {}))
	ed.layout(80, 25)
	vtui.AssertLayoutWithRules(t, newLocalIpsEditor(ed), rules)
}

func TestLocalIpsEditor(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	screen := run(scr, openLocalIpsEditor()...)
	for _, want := range []string{"COCOSMAIL_DELIVERD_LOCAL_IPS: failover", "0.0.0.0 (any IPv4)", ":: (any IPv6)", "(mail.example.com)", "3Mode"} {
		if !strings.Contains(screen, want) {
			t.Errorf("screen misses %q", want)
		}
	}
	// new address with a hostname, moved first, round robin, apply
	events := []*vtinput.InputEvent{key(vtinput.VK_F7)}
	events = append(events, key(vtinput.VK_END))
	for range "0.0.0.0" {
		events = append(events, key(vtinput.VK_BACK))
	}
	events = append(events, typeText("2001:db8::25")...)
	events = append(events, key(vtinput.VK_TAB))
	events = append(events, typeText("mx.example.com")...)
	events = append(events, key(vtinput.VK_RETURN))
	ctrlUp := &vtinput.InputEvent{Type: vtinput.KeyEventType, KeyDown: true, VirtualKeyCode: vtinput.VK_UP, ControlKeyState: vtinput.LeftCtrlPressed}
	events = append(events, ctrlUp, ctrlUp, key(vtinput.VK_F3))
	screen = run(scr, events...)
	if !strings.Contains(screen, "round robin") {
		t.Error("mode not switched")
	}
	run(scr, key(vtinput.VK_F2))
	if got := ed.values["deliverd_local_ips"]; got != "[2001:db8::25]:mx.example.com|0.0.0.0|::" {
		t.Fatalf("deliverd_local_ips = %q", got)
	}
}

func TestLocalIpsEditorNeedsOne(t *testing.T) {
	store := newMemStore()
	ed, scr, _ := setup(t, store)
	events := openLocalIpsEditor()
	events = append(events, key(vtinput.VK_F8), key(vtinput.VK_RETURN), key(vtinput.VK_F8), key(vtinput.VK_RETURN), key(vtinput.VK_F2))
	screen := run(scr, events...)
	if !strings.Contains(screen, "at least one local IP") {
		t.Error("empty list accepted")
	}
	if ed.values["deliverd_local_ips"] != "0.0.0.0&::" {
		t.Errorf("value changed: %q", ed.values["deliverd_local_ips"])
	}
}

func TestAmpersandShown(t *testing.T) {
	_, scr, _ := setup(t, newMemStore())
	screen := run(scr, openLocalIpsEditor()...)
	if !strings.Contains(screen, "Failover (&)") {
		t.Error("& not shown in help text")
	}
	screen = run(scr, key(vtinput.VK_F1))
	if !strings.Contains(screen, "failover (&) and round robin (|)") {
		t.Error("& not shown in help dialog")
	}
}
