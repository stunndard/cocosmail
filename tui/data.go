package tui

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtui"
)

// dataKind is a data section of the configurator: domains, users... Each
// item is a table row, edited in a dialog. Changes are saved with settings.
type dataKind struct {
	name    string // in the section list
	noun    string // one item, in messages
	help    string
	columns []vtui.TableColumn
	count   func(d *core.Data) int
	// key names item i, unique in its kind
	key  func(d *core.Data, i int) string
	cell func(ed *Editor, i, col int) string
	// dialog edits item i, a new one if i is -1
	dialog func(ed *Editor, i int) *vtui.Window
	remove func(d *core.Data, i int)
}

// dataSeparator separates settings sections from data sections in the list
const dataSeparator = "──────────────"

var dataKinds = []*dataKind{domainsKind, usersKind, aliasesKind, relayIPsKind, routesKind, dkimKind}

func kindByName(name string) *dataKind {
	for _, k := range dataKinds {
		if k.name == name {
			return k
		}
	}
	return nil
}

// dataRow is a table row: item i of the kind shown
type dataRow struct {
	ed *Editor
	i  int
}

// GetCellText implements vtui.TableRow
func (r dataRow) GetCellText(col int) string {
	return r.ed.kind.cell(r.ed, r.i, col)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

func without[T any](items []T, i int) []T {
	return append(items[:i:i], items[i+1:]...)
}

// setItem sets item i, or adds x if i is -1
func setItem[T any](items []T, i int, x T) []T {
	if i < 0 {
		return append(items, x)
	}
	items[i] = x
	return items
}

// splitList splits a list separated by spaces, commas or ;
func splitList(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
}

func hasDomain(d *core.Data, name string) bool {
	for _, dom := range d.Domains {
		if dom.Name == name {
			return true
		}
	}
	for _, a := range d.Aliases {
		if a.Alias == name {
			return true
		}
	}
	return false
}

var domainsKind = &dataKind{
	name: "Domains",
	noun: "domain",
	help: "Domains cocosmail accepts mail for. Local: delivered to mailboxes here. Relay: accepted " +
		"and sent on to the domain's servers (or a route). Domain aliases are in Aliases.",
	columns: []vtui.TableColumn{
		{Title: "Domain", Width: 0, MinWidth: 20},
		{Title: "Delivery", Width: 10},
		{Title: "Users", Width: 7},
	},
	count: func(d *core.Data) int { return len(d.Domains) },
	key:   func(d *core.Data, i int) string { return d.Domains[i].Name },
	cell: func(ed *Editor, i, col int) string {
		dom := ed.data.Domains[i]
		switch col {
		case 0:
			return dom.Name
		case 1:
			if dom.Local {
				return "local"
			}
			return "relay"
		}
		n := 0
		for _, u := range ed.data.Users {
			if strings.HasSuffix(u.Login, "@"+dom.Name) {
				n++
			}
		}
		return strconv.Itoa(n)
	},
	dialog: func(ed *Editor, i int) *vtui.Window {
		dom, title := core.DomainData{Local: true}, " New domain "
		if i >= 0 {
			dom, title = ed.data.Domains[i], " Domain "
		}
		return formDialog(ed, title, []itemField{
			{label: "&Domain", value: dom.Name, hint: "example.com"},
		}, []itemCheck{
			{label: "&Local: mailboxes here (off: relayed)", checked: dom.Local},
		}, func(v []string, c []bool) error {
			nd := core.DomainData{Name: strings.ToLower(strings.TrimSpace(v[0])), Local: c[0]}
			if nd.Name == "" {
				return errors.New("the domain is needed")
			}
			next := ed.data.Copy()
			next.Domains = setItem(next.Domains, i, nd)
			return ed.putItem(next, nd.Name)
		})
	},
	remove: func(d *core.Data, i int) { d.Domains = without(d.Domains, i) },
}

var usersKind = &dataKind{
	name: "Users",
	noun: "user",
	help: "Users. With a mailbox, the login is the address it gets mail for. Relay: can send mail " +
		"through cocosmail after logging in. Catch-all: gets the mail of unknown addresses of its domain.",
	columns: []vtui.TableColumn{
		{Title: "Login", Width: 0, MinWidth: 20},
		{Title: "Mailbox", Width: 8},
		{Title: "Relay", Width: 6},
		{Title: "Catch-all", Width: 10},
	},
	count: func(d *core.Data) int { return len(d.Users) },
	key:   func(d *core.Data, i int) string { return d.Users[i].Login },
	cell: func(ed *Editor, i, col int) string {
		u := ed.data.Users[i]
		switch col {
		case 0:
			return u.Login
		case 1:
			return yesNo(u.Mailbox)
		case 2:
			return yesNo(u.Relay)
		}
		return yesNo(u.Catchall)
	},
	dialog: func(ed *Editor, i int) *vtui.Window {
		u, title, hint := core.UserData{Mailbox: true, Relay: true}, " New user ", "at least 6 characters"
		if i >= 0 {
			u, title, hint = ed.data.Users[i], " User ", "empty: unchanged"
		}
		return formDialog(ed, title, []itemField{
			{label: "&Login", value: u.Login, hint: "with a mailbox, its address: john@example.com"},
			{label: "&Password", password: true, hint: hint},
		}, []itemCheck{
			{label: "&Mailbox: gets mail", checked: u.Mailbox},
			{label: "&Relay: can send mail after logging in", checked: u.Relay},
			{label: "C&atch-all: gets mail of unknown addresses", checked: u.Catchall},
		}, func(v []string, c []bool) error {
			nu := u
			nu.Login = strings.ToLower(strings.TrimSpace(v[0]))
			nu.Mailbox, nu.Relay, nu.Catchall = c[0], c[1], c[2]
			if i >= 0 && nu.Login != u.Login && u.Mailbox && ed.savedUser(u.Login) {
				return errors.New("the login of a mailbox can't be changed, its mail would be lost: add a new user")
			}
			if v[1] != "" || i < 0 {
				var err error
				if nu.PasswordHash, nu.DovecotHash, err = core.HashPassword(v[1]); err != nil {
					return err
				}
			}
			next := ed.data.Copy()
			next.Users = setItem(next.Users, i, nu)
			// a mailbox in a new domain: the domain is added, like cocosmail user add
			if t := strings.Split(nu.Login, "@"); nu.Mailbox && len(t) == 2 && t[1] != "" && !hasDomain(next, t[1]) {
				next.Domains = append(next.Domains, core.DomainData{Name: t[1], Local: true})
			}
			return ed.putItem(next, nu.Login)
		})
	},
	remove: func(d *core.Data, i int) { d.Users = without(d.Users, i) },
}

var aliasesKind = &dataKind{
	name: "Aliases",
	noun: "alias",
	help: "An address alias (sales@example.com) delivers to users of its domain and/or to a command. " +
		"Mini list: the alias becomes the sender, bounces come back to it. A domain alias " +
		"(example.org) delivers to the same addresses of a local domain.",
	columns: []vtui.TableColumn{
		{Title: "Alias", Width: 0, MinWidth: 16},
		{Title: "Deliver to", Width: 0, MinWidth: 16},
		{Title: "Pipe", Width: 0, MinWidth: 8},
		{Title: "List", Width: 5},
	},
	count: func(d *core.Data) int { return len(d.Aliases) },
	key:   func(d *core.Data, i int) string { return d.Aliases[i].Alias },
	cell: func(ed *Editor, i, col int) string {
		a := ed.data.Aliases[i]
		switch col {
		case 0:
			return a.Alias
		case 1:
			return strings.Join(a.DeliverTo, " ")
		case 2:
			return a.Pipe
		}
		return yesNo(a.MiniList)
	},
	dialog: func(ed *Editor, i int) *vtui.Window {
		var a core.AliasData
		title := " New alias "
		if i >= 0 {
			a, title = ed.data.Aliases[i], " Alias "
		}
		return formDialog(ed, title, []itemField{
			{label: "&Alias", value: a.Alias, hint: "sales@example.com, or a domain: example.org"},
			{label: "&Deliver to", value: strings.Join(a.DeliverTo, " "), hint: "users; for a domain alias: a local domain"},
			{label: "&Pipe", value: a.Pipe, hint: "command getting the mail on its input"},
		}, []itemCheck{
			{label: "&Mini list: the alias becomes the sender", checked: a.MiniList},
		}, func(v []string, c []bool) error {
			na := core.AliasData{Alias: strings.ToLower(strings.TrimSpace(v[0])), DeliverTo: splitList(v[1]), Pipe: strings.TrimSpace(v[2]), MiniList: c[0]}
			if na.Alias == "" {
				return errors.New("the alias is needed")
			}
			next := ed.data.Copy()
			next.Aliases = setItem(next.Aliases, i, na)
			return ed.putItem(next, na.Alias)
		})
	},
	remove: func(d *core.Data, i int) { d.Aliases = without(d.Aliases, i) },
}

var relayIPsKind = &dataKind{
	name: "Relay IPs",
	noun: "relay IP",
	help: "IP addresses allowed to send mail to any address through cocosmail without logging in, " +
		"like a web server on the same network.",
	columns: []vtui.TableColumn{
		{Title: "IP address", Width: 0, MinWidth: 20},
	},
	count: func(d *core.Data) int { return len(d.RelayIPs) },
	key:   func(d *core.Data, i int) string { return d.RelayIPs[i] },
	cell:  func(ed *Editor, i, col int) string { return ed.data.RelayIPs[i] },
	dialog: func(ed *Editor, i int) *vtui.Window {
		ip, title := "", " New relay IP "
		if i >= 0 {
			ip, title = ed.data.RelayIPs[i], " Relay IP "
		}
		return formDialog(ed, title, []itemField{
			{label: "&IP address", value: ip, hint: "IPv4 or IPv6"},
		}, nil, func(v []string, _ []bool) error {
			parsed := net.ParseIP(strings.Trim(strings.TrimSpace(v[0]), "[]"))
			if parsed == nil {
				return errors.New(v[0] + " is not an IP address")
			}
			next := ed.data.Copy()
			next.RelayIPs = setItem(next.RelayIPs, i, parsed.String())
			return ed.putItem(next, parsed.String())
		})
	},
	remove: func(d *core.Data, i int) { d.RelayIPs = without(d.RelayIPs, i) },
}

var routesKind = &dataKind{
	name: "Routes",
	noun: "route",
	help: "Outgoing mail to a destination domain (* for all) goes through the remote host instead of " +
		"the domain's MX servers, e.g. a provider's relay. Optionally only for an authenticated user " +
		"or a sender. Lower priority first.",
	columns: []vtui.TableColumn{
		{Title: "Destination", Width: 0, MinWidth: 12},
		{Title: "Remote host", Width: 0, MinWidth: 12},
		{Title: "Port", Width: 6},
		{Title: "Prio", Width: 5},
		{Title: "Only for", Width: 0, MinWidth: 8},
		{Title: "Login", Width: 0, MinWidth: 6},
	},
	count: func(d *core.Data) int { return len(d.Routes) },
	key:   func(d *core.Data, i int) string { return d.Routes[i].String() },
	cell: func(ed *Editor, i, col int) string {
		r := ed.data.Routes[i]
		switch col {
		case 0:
			return r.Destination
		case 1:
			return r.RemoteHost
		case 2:
			return strconv.Itoa(r.Port)
		case 3:
			return strconv.Itoa(r.Priority)
		case 4:
			return strings.TrimSpace(r.User + " " + r.MailFrom)
		}
		return r.Login
	},
	dialog: func(ed *Editor, i int) *vtui.Window {
		r, title := core.RouteData{Port: 25}, " New route "
		if i >= 0 {
			r, title = ed.data.Routes[i], " Route "
		}
		return formDialog(ed, title, []itemField{
			{label: "&Destination", value: r.Destination, hint: "domain, * for all"},
			{label: "&Remote host", value: r.RemoteHost},
			{label: "P&ort", value: strconv.Itoa(r.Port), width: 7},
			{label: "Pr&iority", value: strconv.Itoa(r.Priority), width: 7, hint: "lower first"},
			{label: "Local I&Ps", value: r.LocalIPs, hint: "empty: deliverd_local_ips"},
			{label: "&User", value: r.User, hint: "only for this authenticated user or domain"},
			{label: "&Mail from", value: r.MailFrom, hint: "only for this sender or domain"},
			{label: "Lo&gin", value: r.Login, hint: "on the remote host"},
			{label: "Pass&word", value: r.Password, password: !ed.secrets},
		}, nil, func(v []string, _ []bool) error {
			nr := core.RouteData{
				Destination: strings.ToLower(strings.TrimSpace(v[0])),
				RemoteHost:  strings.ToLower(strings.TrimSpace(v[1])),
				LocalIPs:    strings.TrimSpace(v[4]),
				User:        strings.ToLower(strings.TrimSpace(v[5])),
				MailFrom:    strings.ToLower(strings.TrimSpace(v[6])),
				Login:       strings.TrimSpace(v[7]),
				Password:    v[8],
			}
			var err error
			if nr.Port, err = strconv.Atoi(strings.TrimSpace(v[2])); err != nil || nr.Port < 1 || nr.Port > 65535 {
				return errors.New("the port must be a number from 1 to 65535")
			}
			if nr.Priority, err = strconv.Atoi(strings.TrimSpace(v[3])); err != nil || nr.Priority < 0 {
				return errors.New("the priority must be a number, 0 or more")
			}
			if nr.Destination == "" || nr.RemoteHost == "" {
				return errors.New("the destination and the remote host are needed")
			}
			next := ed.data.Copy()
			next.Routes = setItem(next.Routes, i, nr)
			return ed.putItem(next, nr.String())
		})
	},
	remove: func(d *core.Data, i int) { d.Routes = without(d.Routes, i) },
}

var dkimKind = &dataKind{
	name: "DKIM keys",
	noun: "DKIM key",
	help: "DKIM keys sign outgoing mail of a domain. The public key must be published in DNS: " +
		"F6 shows the TXT record. A new key needs a new DNS record.",
	columns: []vtui.TableColumn{
		{Title: "Domain", Width: 0, MinWidth: 16},
		{Title: "Selector", Width: 12},
		{Title: "DNS record name", Width: 0, MinWidth: 20},
	},
	count: func(d *core.Data) int { return len(d.Dkim) },
	key:   func(d *core.Data, i int) string { return d.Dkim[i].Domain },
	cell: func(ed *Editor, i, col int) string {
		k := ed.data.Dkim[i]
		switch col {
		case 0:
			return k.Domain
		case 1:
			return k.Selector
		}
		return k.Selector + "._domainkey." + k.Domain
	},
	dialog: func(ed *Editor, i int) *vtui.Window {
		k, title := core.DkimData{Selector: time.Now().Format("20060102")}, " New DKIM key "
		var checks []itemCheck
		if i >= 0 {
			k, title = ed.data.Dkim[i], " DKIM key "
			checks = []itemCheck{{label: "&New key: the DNS record must be changed"}}
		}
		return formDialog(ed, title, []itemField{
			{label: "&Domain", value: k.Domain, hint: "whose outgoing mail is signed"},
			{label: "&Selector", value: k.Selector, hint: "name of the key in DNS: new key, new selector"},
		}, checks, func(v []string, c []bool) error {
			nk := k
			nk.Domain = strings.ToLower(strings.TrimSpace(v[0]))
			nk.Selector = strings.TrimSpace(v[1])
			if i < 0 || c[0] {
				var err error
				if nk.PrivateKey, err = core.NewDkimKey(); err != nil {
					return err
				}
			}
			next := ed.data.Copy()
			next.Dkim = setItem(next.Dkim, i, nk)
			return ed.putItem(next, nk.Domain)
		})
	},
	remove: func(d *core.Data, i int) { d.Dkim = without(d.Dkim, i) },
}

// dnsDialog shows the DNS record of DKIM key k
func dnsDialog(ed *Editor, k core.DkimData) *vtui.Window {
	name, value, err := core.DkimDNSRecord(k)
	if err != nil {
		value = err.Error()
	}
	w := ed.width - 4
	if w > 76 {
		w = 76
	}
	// the value has no spaces: cut in lines
	var lines []string
	for len(value) > w-4 {
		lines = append(lines, value[:w-4])
		value = value[w-4:]
	}
	lines = append(lines, value)
	h := len(lines) + 12
	x1, y1 := (ed.width-w)/2, (ed.height-1-h)/2
	dlg := vtui.NewDialog(x1, y1, x1+w-1, y1+h-1, " DKIM DNS record of "+k.Domain+" ")
	y := y1 + 2
	for _, t := range []string{"TXT record " + name + ", value:", ""} {
		dlg.AddItem(vtui.NewText(x1+2, y, literal(t), 0))
		y++
	}
	for _, l := range lines {
		dlg.AddItem(vtui.NewText(x1+2, y, literal(l), 0))
		y++
	}
	y++
	for _, t := range []string{"Also: cocosmail dkim getdnsrecord " + k.Domain, "(needs the key saved)"} {
		dlg.AddItem(vtui.NewText(x1+2, y, literal(t), 0))
		y++
	}
	ok := vtui.NewButton(0, 0, "&Ok")
	ok.IsDefault = true
	by := y1 + h - 3
	ok.SetPosition(x1+(w-6)/2, by, x1+(w-6)/2+ok.X2-ok.X1, by)
	ok.OnClick = func() { dlg.SetExitCode(1) }
	dlg.AddItem(ok)
	return dlg
}

// savedUser returns true if user login is saved, not only added here
func (ed *Editor) savedUser(login string) bool {
	for _, u := range ed.savedData.Users {
		if u.Login == login {
			return true
		}
	}
	return false
}

// putItem makes next the data being edited, name is the item added or
// changed: it must be unique, and next must not have new errors
func (ed *Editor) putItem(next *core.Data, name string) error {
	k := ed.kind
	n := 0
	for j := 0; j < k.count(next); j++ {
		if k.key(next, j) == name {
			n++
		}
	}
	if n > 1 {
		return fmt.Errorf("%s %s already exists", k.noun, name)
	}
	return ed.setData(next, name)
}

// setData makes next the data being edited, if it has no new errors.
// Errors already there (e.g. from the database) don't block other changes.
// The item named select is selected.
func (ed *Editor) setData(next *core.Data, sel string) error {
	next.Sort()
	before := make(map[string]bool)
	for _, e := range core.ValidateData(ed.data) {
		before[e.Error()] = true
	}
	var msgs []string
	for _, e := range core.ValidateData(next) {
		if !before[e.Error()] {
			msgs = append(msgs, e.Error())
		}
	}
	if len(msgs) > 5 {
		msgs = append(msgs[:5], fmt.Sprintf("and %d more", len(msgs)-5))
	}
	if len(msgs) > 0 {
		return errors.New(strings.Join(msgs, "\n"))
	}
	ed.data = next
	ed.refreshData()
	for j := 0; j < ed.kind.count(ed.data); j++ {
		if ed.kind.key(ed.data, j) == sel {
			ed.table.ClearSearch()
			ed.table.SetSelectPos(j)
		}
	}
	ed.updateTitle()
	return nil
}

// editItem edits the selected item, or a new one
func (ed *Editor) editItem(isNew bool) {
	i := ed.selectedItem()
	if isNew || i < 0 {
		i = -1
	}
	vtui.FrameManager.Push(ed.kind.dialog(ed, i))
}

// deleteItem deletes the selected item, after confirmation
func (ed *Editor) deleteItem() {
	i := ed.selectedItem()
	if i < 0 {
		return
	}
	name := ed.kind.key(ed.data, i)
	dlg := vtui.ShowMessage("Delete", literal("Delete "+ed.kind.noun+" "+name+"?"), []string{"&Delete", "&Cancel"})
	dlg.OnResult = func(code int) {
		if code != 0 {
			return
		}
		next := ed.data.Copy()
		ed.kind.remove(next, i)
		if err := ed.setData(next, ""); err != nil {
			ed.message("Error", "Not deleted:\n"+err.Error())
		}
	}
}

// showDNS shows the DNS record of the selected DKIM key
func (ed *Editor) showDNS() {
	if i := ed.selectedItem(); i >= 0 {
		vtui.FrameManager.Push(dnsDialog(ed, ed.data.Dkim[i]))
	}
}

// selectedItem returns the index of the selected item, -1 if there's none
func (ed *Editor) selectedItem() int {
	if ed.kind == nil || ed.kind.count(ed.data) == 0 {
		return -1
	}
	pos := ed.table.SelectPos
	if ed.table.RowAt(pos) >= 0 {
		pos = ed.table.RowAt(pos)
	}
	if pos < 0 || pos >= ed.kind.count(ed.data) {
		return -1
	}
	return pos
}

// showData shows the items of a data kind
func (ed *Editor) showData(k *dataKind) {
	ed.kind = k
	ed.table.Columns = k.columns
	ed.table.ClearSearch()
	ed.table.SelectPos, ed.table.TopPos = 0, 0
	ed.refreshData()
}

// refreshData shows the items again
func (ed *Editor) refreshData() {
	rows := make([]vtui.TableRow, ed.kind.count(ed.data))
	for i := range rows {
		rows[i] = dataRow{ed, i}
	}
	ed.table.SetRows(rows)
	ed.updateDescription()
}
