package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/unxed/vtinput"
)

// TestDumpScreen prints a screen, to look at it:
// COCOSMAIL_TUI_DUMP=main|section|help|quit go test -tags goffi_static -run TestDumpScreen -v ./tui
func TestDumpScreen(t *testing.T) {
	what := os.Getenv("COCOSMAIL_TUI_DUMP")
	if what == "" {
		t.Skip("set COCOSMAIL_TUI_DUMP")
	}
	_, scr, _ := setup(t, newMemStore())
	var events []*vtinput.InputEvent
	switch what {
	case "section":
		events = []*vtinput.InputEvent{key(vtinput.VK_TAB), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_DOWN), key(vtinput.VK_RETURN)}
	case "help":
		events = []*vtinput.InputEvent{key(vtinput.VK_F1)}
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
