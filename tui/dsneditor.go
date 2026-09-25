package tui

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// dsnSettings are the settings edited as a list of listeners
var dsnSettings = map[string]string{
	"smtpd_dsns": "smtp",
	"pop3d_dsns": "pop3",
}

// DsnEditor edits a list of listeners (smtpd_dsns, pop3d_dsns) as a table,
// one listener per row
type DsnEditor struct {
	*vtui.Window
	ed     *Editor
	key    string
	proto  string // smtp or pop3
	dsns   []core.DsnFields
	orig   string
	table  *vtui.Table
	help   [2]*vtui.Text
	x1, y1 int
	x2, y2 int
}

// dsnRow is a table row
type dsnRow struct {
	d core.DsnFields
}

// GetCellText implements vtui.TableRow
func (r dsnRow) GetCellText(col int) string {
	switch col {
	case 0:
		if r.d.IP == "" || r.d.IP == "::" || r.d.IP == "0.0.0.0" {
			return r.d.IP + " (all)"
		}
		return r.d.IP
	case 1:
		return r.d.Port
	case 2:
		return r.d.Hostname
	case 3:
		return r.d.SSL
	default:
		return r.d.Cert
	}
}

// newDsnEditor returns the listener editor of setting key, over ed
func newDsnEditor(ed *Editor, key string) *DsnEditor {
	de := &DsnEditor{ed: ed, key: key, proto: dsnSettings[key], orig: ed.values[key]}
	for _, s := range strings.Split(ed.values[key], ";") {
		if strings.TrimSpace(s) != "" {
			de.dsns = append(de.dsns, core.SplitDsn(s))
		}
	}
	de.x1, de.y1, de.x2, de.y2 = 3, 2, ed.width-4, ed.height-4
	de.Window = vtui.NewDialog(de.x1, de.y1, de.x2, de.y2, " "+core.SettingEnvName(key)+" ")
	de.table = vtui.NewTable(de.x1+2, de.y1+2, de.x2-de.x1-3, de.y2-de.y1-6, []vtui.TableColumn{
		{Title: "IP address", Width: 0, MinWidth: 12},
		{Title: "Port", Width: 6},
		{Title: "Hostname", Width: 0, MinWidth: 10},
		{Title: "SSL", Width: 6},
		{Title: "Certificate", Width: 0, MinWidth: 10},
	})
	de.table.ShowHeader = true
	de.table.SetPosition(de.x1+2, de.y1+2, de.x2-2, de.y2-5)
	de.table.OnAction = func(int) { de.editRow(false) }
	de.AddItem(de.table)
	for i := range de.help {
		y := de.y2 - 3 + i
		de.help[i] = vtui.NewText(de.x1+2, y, "", 0)
		de.help[i].SetPosition(de.x1+2, y, de.x2-2, y)
		de.AddItem(de.help[i])
	}
	lines := wrap("One row per listener. IP empty, :: or 0.0.0.0: all IPv4 and IPv6 addresses. "+
		"ssl: TLS from the start, nossl: STARTTLS available. Certificate: ssl/"+de.proto+"-NAME.crt and .key", de.x2-de.x1-4)
	for i := 0; i < len(de.help) && i < len(lines); i++ {
		de.help[i].SetText(lines[i])
	}
	de.refresh()
	return de
}

func (de *DsnEditor) refresh() {
	rows := make([]vtui.TableRow, len(de.dsns))
	for i, d := range de.dsns {
		rows[i] = dsnRow{d}
	}
	de.table.SetRows(rows)
	if de.table.SelectPos >= len(de.dsns) {
		de.table.SelectPos = len(de.dsns) - 1
	}
	if de.table.SelectPos < 0 {
		de.table.SelectPos = 0
	}
	title := " " + core.SettingEnvName(de.key) + " "
	if de.value() != de.orig {
		title += "(changed) "
	}
	de.SetTitle(title)
}

// value returns the listeners as the setting value
func (de *DsnEditor) value() string {
	parts := make([]string, len(de.dsns))
	for i, d := range de.dsns {
		parts[i] = d.String()
	}
	return strings.Join(parts, ";")
}

// GetKeyLabels replace the key bar of the main window
func (de *DsnEditor) GetKeyLabels() *vtui.KeySet {
	return keyLabels(de.ed.width, map[int][2]string{
		1: {"Help", "Help"}, 2: {"Apply", "Ok"}, 4: {"Edit", "Edit"}, 5: {"Copy", "Copy"},
		7: {"New", "New"}, 8: {"Delete", "Del"}, 10: {"Close", "End"},
	})
}

// ProcessKey handles the function keys, other keys go to the table
func (de *DsnEditor) ProcessKey(e *vtinput.InputEvent) bool {
	if e.KeyDown {
		switch e.VirtualKeyCode {
		case vtinput.VK_F1:
			vtui.FrameManager.Push(helpDialog(de.ed, dsnHelpKeys))
			return true
		case vtinput.VK_F2:
			de.apply()
			return true
		case vtinput.VK_F4:
			de.editRow(false)
			return true
		case vtinput.VK_F5:
			if len(de.dsns) > 0 {
				de.dsns = append(de.dsns, de.dsns[de.table.SelectPos])
				de.table.SelectPos = len(de.dsns) - 1
				de.refresh()
			}
			return true
		case vtinput.VK_F7, vtinput.VK_INSERT:
			de.editRow(true)
			return true
		case vtinput.VK_F8, vtinput.VK_DELETE:
			de.deleteRow()
			return true
		case vtinput.VK_F10, vtinput.VK_ESCAPE:
			de.cancel()
			return true
		}
	}
	return de.Window.ProcessKey(e)
}

// dsnHelpKeys are shown by the help dialog of the listener editor
var dsnHelpKeys = [][2]string{
	{"F2", "Apply the listeners to the setting and close"},
	{"F4, Enter", "Edit the selected listener"},
	{"F5", "Copy the selected listener"},
	{"F7, Ins", "Add a listener"},
	{"F8, Del", "Delete the selected listener"},
	{"F10, Esc", "Close without applying, asks if changed"},
}

func (de *DsnEditor) deleteRow() {
	if len(de.dsns) == 0 {
		return
	}
	i := de.table.SelectPos
	dlg := vtui.ShowMessage("Delete", "Delete listener "+de.dsns[i].String()+"?", []string{"&Delete", "&Cancel"})
	dlg.OnResult = func(code int) {
		if code == 0 {
			de.dsns = append(de.dsns[:i], de.dsns[i+1:]...)
			de.refresh()
		}
	}
}

// apply sets the listeners in the main editor and closes
func (de *DsnEditor) apply() {
	v := de.value()
	if err := core.ValidateSetting(de.key, v); err != nil {
		de.ed.message("Error", err.Error())
		return
	}
	de.ed.set(de.key, v)
	de.SetExitCode(1)
}

func (de *DsnEditor) cancel() {
	if de.value() == de.orig {
		de.SetExitCode(-1)
		return
	}
	dlg := vtui.ShowMessage("Cancel", "The listeners were changed.", []string{"&Apply", "&Discard", "&Cancel"})
	dlg.OnResult = func(code int) {
		switch code {
		case 0:
			de.apply()
		case 1:
			de.SetExitCode(-1)
		}
	}
}

// newDsn returns the defaults of a new listener
func (de *DsnEditor) newDsn() core.DsnFields {
	host := de.ed.values["me"]
	if de.proto == "pop3" {
		return core.DsnFields{Port: "995", Hostname: host, SSL: "ssl", Cert: host}
	}
	return core.DsnFields{Port: "25", Hostname: host, SSL: "nossl", Cert: host}
}

// editRow edits the selected listener, or a new one
func (de *DsnEditor) editRow(isNew bool) {
	if !isNew && len(de.dsns) == 0 {
		isNew = true
	}
	d := de.newDsn()
	if !isNew {
		d = de.dsns[de.table.SelectPos]
	}
	dlg := de.rowDialog(d, isNew, func(nd core.DsnFields) {
		if isNew {
			de.dsns = append(de.dsns, nd)
			de.table.SelectPos = len(de.dsns) - 1
		} else {
			de.dsns[de.table.SelectPos] = nd
		}
		de.refresh()
	})
	vtui.FrameManager.Push(dlg)
}

// rowDialog returns the dialog editing one listener, done is called with it on Ok
func (de *DsnEditor) rowDialog(d core.DsnFields, isNew bool, done func(core.DsnFields)) *vtui.Window {
	const labelW = 13
	w := 64
	h := 17
	x1, y1 := (de.ed.width-w)/2, (de.ed.height-1-h)/2
	title := " Listener "
	if isNew {
		title = " New listener "
	}
	dlg := vtui.NewDialog(x1, y1, x1+w-1, y1+h-1, title)
	x, ex := x1+2, x1+2+labelW+1
	field := func(y int, label, value, hint string, width int) *vtui.Edit {
		edit := newEdit(ex, y, width, value)
		dlg.AddItem(vtui.NewLabel(x, y, label, edit))
		dlg.AddItem(edit)
		if hint != "" {
			dlg.AddItem(vtui.NewText(ex, y+1, hint, 0))
		}
		return edit
	}
	ip := field(y1+2, "&IP address", d.IP, "empty, :: or 0.0.0.0: all addresses", w-labelW-5)
	port := field(y1+5, "&Port", d.Port, "", 7)
	host := field(y1+7, "&Hostname", d.Hostname, "in the greeting and Received headers", w-labelW-5)
	ssl := vtui.NewCheckbox(ex, y1+10, "&SSL from the start (off: STARTTLS)", false)
	if d.SSL == "ssl" {
		ssl.State = 1
	}
	dlg.AddItem(ssl)
	cert := field(y1+12, "&Certificate", d.Cert, "", w-labelW-5)
	ok := vtui.NewButton(0, 0, "&Ok")
	ok.IsDefault = true
	cancel := vtui.NewButton(0, 0, "&Cancel")
	by := y1 + h - 3
	ok.SetPosition(x1+w/2-12, by, x1+w/2-12+ok.X2-ok.X1, by)
	cancel.SetPosition(x1+w/2+2, by, x1+w/2+2+cancel.X2-cancel.X1, by)
	ok.OnClick = func() {
		nd := core.DsnFields{
			IP:       strings.Trim(strings.TrimSpace(ip.GetText()), "[]"),
			Port:     strings.TrimSpace(port.GetText()),
			Hostname: strings.TrimSpace(host.GetText()),
			SSL:      "nossl",
			Cert:     strings.TrimSpace(cert.GetText()),
		}
		if ssl.State == 1 {
			nd.SSL = "ssl"
		}
		if err := de.checkDsn(nd); err != nil {
			de.ed.message("Error", err.Error())
			return
		}
		done(nd)
		dlg.SetExitCode(1)
	}
	cancel.OnClick = func() { dlg.SetExitCode(-1) }
	dlg.AddItem(ok)
	dlg.AddItem(cancel)
	return dlg
}

// checkDsn checks one listener
func (de *DsnEditor) checkDsn(d core.DsnFields) error {
	if d.IP != "" && net.ParseIP(strings.SplitN(d.IP, "%", 2)[0]) == nil {
		return errors.New(d.IP + " is not an IP address")
	}
	if p, err := strconv.Atoi(d.Port); err != nil || p < 1 || p > 65535 {
		return errors.New("the port must be a number from 1 to 65535")
	}
	if d.Hostname == "" || d.Cert == "" {
		return errors.New("the hostname and the certificate name are needed")
	}
	if strings.ContainsAny(d.Hostname+d.Cert, ":; ") {
		return errors.New("the hostname and the certificate name can't contain : ; or spaces")
	}
	dsns, err := core.GetDsnsFromString(d.String())
	if err != nil {
		return err
	}
	if de.proto == "pop3" && !dsns[0].Ssl && !dsns[0].TcpAddr.IP.IsLoopback() {
		return errors.New("POP3 without SSL sends passwords in clear text: it's only allowed on a loopback address (127.0.0.1, ::1)")
	}
	return nil
}
