package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/unxed/vtinput"
)

// TestDumpScreen prints a screen, to look at it:
// COCOSMAIL_TUI_DUMP=main|section|help|quit|users|userdlg|routedlg|dkimdns go test -tags goffi_static -run TestDumpScreen -v ./tui
func TestDumpScreen(t *testing.T) {
	what := os.Getenv("COCOSMAIL_TUI_DUMP")
	if what == "" {
		t.Skip("set COCOSMAIL_TUI_DUMP")
	}
	store := newMemStore()
	store.values["smtpd_dsns"] = "[::]:25:mail.example.com:nossl:example.com;[::]:587:mail.example.com:nossl:example.com;[::]:465:mail.example.com:ssl:example.com"
	_, scr, _ := setup(t, store)
	var events []*vtinput.InputEvent
	switch what {
	case "section":
		events = []*vtinput.InputEvent{key(vtinput.VK_TAB), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_RETURN)}
	case "help":
		events = []*vtinput.InputEvent{key(vtinput.VK_F1)}
	case "dsn", "dsnrow":
		events = openDsnEditor()
		if what == "dsnrow" {
			events = append(events, key(vtinput.VK_F7))
		}
	case "localips", "localipsrow":
		events = openLocalIpsEditor()
		if what == "localipsrow" {
			events = append(events, key(vtinput.VK_F7))
		}
	case "deliverd":
		events = []*vtinput.InputEvent{key(vtinput.VK_TAB), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), key(vtinput.VK_DOWN)}
	case "edit":
		events = []*vtinput.InputEvent{key(vtinput.VK_F4)}
	case "editsel":
		events = []*vtinput.InputEvent{key(vtinput.VK_F4), {Type: vtinput.KeyEventType, KeyDown: true, VirtualKeyCode: vtinput.VK_A, ControlKeyState: vtinput.LeftCtrlPressed}}
	case "users", "userdlg":
		*store = *dataStore(t)
		_, scr, _ = setup(t, store)
		events = toKind(usersKind)
		if what == "userdlg" {
			events = append(events, key(vtinput.VK_F4))
		}
	case "routedlg":
		events = append(toKind(routesKind), key(vtinput.VK_F7))
	case "dkimdns":
		events = append(toKind(dkimKind), key(vtinput.VK_F7))
		events = append(events, typeText("example.com")...)
		events = append(events, key(vtinput.VK_RETURN), key(vtinput.VK_F6))
	case "quit":
		events = []*vtinput.InputEvent{key(vtinput.VK_DOWN), key(vtinput.VK_RETURN), key(vtinput.VK_F10)}
	}
	screen := run(scr, events...)
	text := screen
	if os.Getenv("COCOSMAIL_TUI_DUMP_ATTR") == "" {
		text = strings.SplitN(screen, "--- CELL METADATA", 2)[0]
	}
	t.Log("\n" + text)
}
