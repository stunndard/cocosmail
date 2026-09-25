package tui

import (
	"strings"
	"testing"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// toKind selects data section k from the settings, focus on its items
func toKind(k *dataKind) []*vtinput.InputEvent {
	events := []*vtinput.InputEvent{key(vtinput.VK_TAB), key(vtinput.VK_END)}
	for i := len(dataKinds) - 1; dataKinds[i] != k; i-- {
		events = append(events, key(vtinput.VK_UP))
	}
	return append(events, key(vtinput.VK_RETURN))
}

func dataStore(t *testing.T) *memStore {
	store := newMemStore()
	hash, dove, err := core.HashPassword("secret1")
	if err != nil {
		t.Fatal(err)
	}
	store.data = &core.Data{
		Domains: []core.DomainData{{Name: "example.com", Local: true}},
		Users:   []core.UserData{{Login: "john@example.com", PasswordHash: hash, DovecotHash: dove, Mailbox: true, Relay: true}},
	}
	return store
}

func TestDataSectionsListed(t *testing.T) {
	ed, scr, _ := setup(t, dataStore(t))
	screen := run(scr, toKind(usersKind)...)
	for _, want := range []string{dataSeparator, "Domains", "DKIM keys", "Login", "Mailbox", "john@example.com", "7New", "8Delete"} {
		if !strings.Contains(screen, want) {
			t.Errorf("screen misses %q", want)
		}
	}
	if ed.kind != usersKind || ed.selected() != "" {
		t.Fatalf("kind %v, selected %q", ed.kind, ed.selected())
	}
	// up from domains: the separator is skipped
	run(scr, key(vtinput.VK_TAB), key(vtinput.VK_UP), key(vtinput.VK_UP))
	if ed.kind != nil || ed.sections.SelectPos != len(ed.sections.Items)-len(dataKinds)-2 {
		t.Errorf("not on all settings: %d", ed.sections.SelectPos)
	}
}

func TestDataAddUser(t *testing.T) {
	store := dataStore(t)
	ed, scr, _ := setup(t, store)
	events := toKind(usersKind)
	events = append(events, key(vtinput.VK_F7))
	events = append(events, typeText("Jane@Example.org")...)
	events = append(events, key(vtinput.VK_TAB))
	events = append(events, typeText("secret2")...)
	events = append(events, key(vtinput.VK_RETURN))
	screen := run(scr, events...)
	if len(ed.data.Users) != 2 || ed.data.Users[0].Login != "jane@example.org" {
		t.Fatalf("user not added: %+v", ed.data.Users)
	}
	// its domain comes with it
	if len(ed.data.Domains) != 2 || ed.data.Domains[1].Name != "example.org" {
		t.Fatalf("domain not added: %+v", ed.data.Domains)
	}
	if !strings.Contains(screen, "(2 changed)") {
		t.Error("changes not counted")
	}
	if store.dataSaves != 0 {
		t.Fatal("saved before F2")
	}
	screen = run(scr, key(vtinput.VK_F2))
	for _, want := range []string{"add domain example.org", "add user jane@example.org"} {
		if !strings.Contains(screen, want) {
			t.Errorf("save dialog misses %q", want)
		}
	}
	run(scr, key(vtinput.VK_RETURN))
	if store.dataSaves != 1 || len(store.data.Users) != 2 {
		t.Fatalf("not saved: %+v", store.data)
	}
	if ed.changes() != 0 {
		t.Error("still changed after save")
	}
}

func TestDataRejects(t *testing.T) {
	store := dataStore(t)
	ed, scr, _ := setup(t, store)
	// short password
	events := toKind(usersKind)
	events = append(events, key(vtinput.VK_F7))
	events = append(events, typeText("jane@example.com")...)
	events = append(events, key(vtinput.VK_TAB))
	events = append(events, typeText("abc")...)
	events = append(events, key(vtinput.VK_RETURN))
	screen := run(scr, events...)
	if !strings.Contains(screen, "at least 6 chars") || len(ed.data.Users) != 1 {
		t.Fatal("short password accepted")
	}
	run(scr, key(vtinput.VK_RETURN), key(vtinput.VK_ESCAPE))

	// a domain with users can't be deleted
	events = []*vtinput.InputEvent{key(vtinput.VK_TAB), key(vtinput.VK_UP), key(vtinput.VK_RETURN), key(vtinput.VK_F8), key(vtinput.VK_RETURN)}
	screen = run(scr, events...)
	if ed.kind != domainsKind {
		t.Fatalf("kind %v", ed.kind)
	}
	if !strings.Contains(screen, "Not deleted") || len(ed.data.Domains) != 1 {
		t.Fatal("domain with users deleted")
	}
	// existing errors don't block other changes
	ed.data.Users = append(ed.data.Users, core.UserData{Login: "broken@example.com", Mailbox: true})
	if err := ed.setData(&core.Data{Domains: ed.data.Domains, Users: ed.data.Users, RelayIPs: []string{"192.0.2.1"}}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestDataDkim(t *testing.T) {
	store := dataStore(t)
	ed, scr, _ := setup(t, store)
	events := toKind(dkimKind)
	events = append(events, key(vtinput.VK_F7))
	events = append(events, typeText("example.com")...)
	events = append(events, key(vtinput.VK_RETURN))
	screen := run(scr, events...)
	if len(ed.data.Dkim) != 1 || !strings.Contains(ed.data.Dkim[0].PrivateKey, "RSA PRIVATE KEY") {
		t.Fatalf("no key: %+v", ed.data.Dkim)
	}
	if !strings.Contains(screen, "6DNS") {
		t.Error("no DNS key")
	}
	screen = run(scr, key(vtinput.VK_F6))
	name := ed.data.Dkim[0].Selector + "._domainkey.example.com"
	if !strings.Contains(screen, name) || !strings.Contains(screen, "v=DKIM1;k=rsa") {
		t.Error("DNS record not shown")
	}
}

func TestDataDialogsLayout(t *testing.T) {
	ed, _, _ := setup(t, dataStore(t))
	ed.data.Routes = []core.RouteData{{Destination: "*", RemoteHost: "smtp.example.net", Port: 587}}
	key, _ := core.NewDkimKey()
	ed.data.Dkim = []core.DkimData{{Domain: "example.com", Selector: "s1", PrivateKey: key}}
	for _, size := range [][2]int{{testW, testH}, {80, 24}} {
		ed.layout(size[0], size[1])
		for _, k := range dataKinds {
			ed.showData(k)
			vtui.AssertLayout(t, k.dialog(ed, -1))
		}
		vtui.AssertLayout(t, dnsDialog(ed, ed.data.Dkim[0]))
	}
}
