package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stunndard/cocosmail/core"
)

func TestFileStoreData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cocosmail.yaml")
	s := &FileStore{Path: path}
	d, err := s.LoadData()
	if err != nil || !d.Empty() {
		t.Fatalf("new file: %v %+v", err, d)
	}
	if err := s.Save(map[string]string{"me": "mail.example.com"}); err != nil {
		t.Fatal(err)
	}
	next := &core.Data{Domains: []core.DomainData{{Name: "example.com", Local: true}}, RelayIPs: []string{"192.0.2.1"}}
	if err := s.SaveData(d, next); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	for _, want := range []string{"  me: mail.example.com\n", "domains:\n  - name: example.com\n", "relay_ips:\n  - 192.0.2.1\n", "# --- general ---"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("file misses %q:\n%s", want, content)
		}
	}
	d, err = s.LoadData()
	if err != nil || len(d.Domains) != 1 || len(d.RelayIPs) != 1 {
		t.Fatalf("%v %+v", err, d)
	}

	// an old style file is not rewritten
	old := filepath.Join(t.TempDir(), "old.cfg")
	os.WriteFile(old, []byte("COCOSMAIL_ME=mail.example.com\n"), 0600)
	err = (&FileStore{Path: old}).SaveData(&core.Data{}, next)
	if err == nil || !strings.Contains(err.Error(), "convert it first") {
		t.Fatalf("old file written: %v", err)
	}
}
