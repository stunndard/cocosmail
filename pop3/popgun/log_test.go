package popgun

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stunndard/cocosmail/pop3/popgun/backends"
)

// logBackend records log lines
type logBackend struct {
	backends.DummyBackend
	mu    sync.Mutex
	lines []string
}

func (b *logBackend) Log(s string, level int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lvl := map[int]string{LOG_INFO: "INFO", LOG_DEBUG: "DEBUG", LOG_ERROR: "ERROR"}[level]
	b.lines = append(b.lines, lvl+" "+s)
}

func TestClientLog(t *testing.T) {
	s, c := net.Pipe()
	backend := &logBackend{}
	client := newClient(backends.DummyAuthorizator{}, backend, "POPgun")
	done := make(chan struct{})
	go func() {
		client.handle(s)
		close(done)
	}()

	reader := bufio.NewReader(c)
	readReply := func(multiline bool) {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if !multiline || line == ".\r\n" {
				return
			}
		}
	}
	readReply(false)
	for _, cmd := range []string{"USER alice", "PASS secret123", "LIST", "RETR 1", "DELE 1", "QUIT"} {
		fmt.Fprintf(c, "%s\r\n", cmd)
		readReply(cmd == "LIST")
		if cmd == "RETR 1" {
			readReply(true)
		}
	}
	<-done
	c.Close()

	backend.mu.Lock()
	log := strings.Join(backend.lines, "\n")
	backend.mu.Unlock()

	// every line is ID-REMOTE-message
	prefix := regexp.MustCompile(`^(INFO|DEBUG|ERROR) [0-9a-f]{40}-pipe-`)
	for _, l := range backend.lines {
		if !prefix.MatchString(l) {
			t.Errorf("line without session prefix: %s", l)
		}
	}
	for _, want := range []string{
		"INFO .*-starting new session$",
		"DEBUG .*-> \\+OK POPgun POP3 server ready$",
		"DEBUG .*-< USER alice$",
		"DEBUG .*-< PASS \\*\\*\\*\\*\\*\\*\\*\\*$",
		"INFO .*-login alice$",
		"DEBUG .*-< LIST$",
		"INFO .*-RETR 1 - 21 bytes$",
		"DEBUG .*-> \\(message, 1 lines\\)$",
		"INFO .*-DELE 1$",
		"DEBUG .*-< QUIT$",
		"DEBUG .*-> \\+OK Goodbye$",
		"INFO .*-EOT$",
	} {
		if !regexp.MustCompile("(?m)" + want).MatchString(log) {
			t.Errorf("log misses %q:\n%s", want, log)
		}
	}
	for _, secret := range []string{"secret123", "this is dummy message"} {
		if strings.Contains(log, secret) {
			t.Errorf("log contains %q:\n%s", secret, log)
		}
	}
}
