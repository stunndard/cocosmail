package tui

import (
	"os"
	"strings"
	"testing"
)

// TestDumpScreen prints the screen, run with COCOSMAIL_TUI_DUMP=1 to look at it
func TestDumpScreen(t *testing.T) {
	if os.Getenv("COCOSMAIL_TUI_DUMP") == "" {
		t.Skip("set COCOSMAIL_TUI_DUMP=1")
	}
	store := newMemStore()
	_, scr, _ := setup(t, store)
	screen := run(scr, typeText("smtpd_ds")...)
	text := strings.SplitN(screen, "\n\n", 2)[0]
	t.Log("\n" + text)
}
