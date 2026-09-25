package tui

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtui"
)

// dsnSettings are the settings edited as a list of listeners
var dsnSettings = map[string]string{
	"smtpd_dsns": "smtp",
	"pop3d_dsns": "pop3",
}

// DsnEditor edits a list of listeners (smtpd_dsns, pop3d_dsns), one per row
type DsnEditor struct {
	*listEditor[core.DsnFields]
	proto string // smtp or pop3
}

// newDsnEditor returns the listener editor of setting key, over ed
func newDsnEditor(ed *Editor, key string) *DsnEditor {
	de := &DsnEditor{proto: dsnSettings[key]}
	de.listEditor = newListEditor[core.DsnFields](ed, key, "listener", "listeners", []vtui.TableColumn{
		{Title: "IP address", Width: 0, MinWidth: 12},
		{Title: "Port", Width: 6},
		{Title: "Hostname", Width: 0, MinWidth: 10},
		{Title: "SSL", Width: 6},
		{Title: "Certificate", Width: 0, MinWidth: 10},
	})
	de.value = func(dsns []core.DsnFields) string {
		parts := make([]string, len(dsns))
		for i, d := range dsns {
			parts[i] = d.String()
		}
		return strings.Join(parts, ";")
	}
	de.cell = dsnCell
	de.newItem = de.newDsn
	de.dialog = de.rowDialog
	de.helpText = func() string {
		return "One row per listener. IP empty, :: or 0.0.0.0: all IPv4 and IPv6 addresses. " +
			"ssl: TLS from the start, nossl: STARTTLS available. Certificate: ssl/" + de.proto + "-NAME.crt and .key"
	}
	for _, s := range strings.Split(ed.values[key], ";") {
		if strings.TrimSpace(s) != "" {
			de.items = append(de.items, core.SplitDsn(s))
		}
	}
	de.refresh()
	return de
}

func dsnCell(d core.DsnFields, col int) string {
	switch col {
	case 0:
		if d.IP == "" || d.IP == "::" || d.IP == "0.0.0.0" {
			return d.IP + " (all)"
		}
		return d.IP
	case 1:
		return d.Port
	case 2:
		return d.Hostname
	case 3:
		return d.SSL
	default:
		return d.Cert
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

// rowDialog returns the dialog editing one listener, done is called with it on Ok
func (de *DsnEditor) rowDialog(d core.DsnFields, isNew bool, done func(core.DsnFields)) *vtui.Window {
	title := " Listener "
	if isNew {
		title = " New listener "
	}
	var ssl *vtui.Checkbox
	return de.itemDialog(title, []itemField{
		{label: "&IP address", value: d.IP, hint: "empty, :: or 0.0.0.0: all addresses"},
		{label: "&Port", value: d.Port, width: 7},
		{label: "&Hostname", value: d.Hostname, hint: "in the greeting and Received headers"},
		{label: "&Certificate", value: d.Cert},
	}, func(dlg *vtui.Window, x, y int) int {
		ssl = vtui.NewCheckbox(x, y, "&SSL from the start (off: STARTTLS)", false)
		if d.SSL == "ssl" {
			ssl.State = 1
		}
		dlg.AddItem(ssl)
		return y + 2
	}, func(v []string) error {
		nd := core.DsnFields{
			IP:       strings.Trim(strings.TrimSpace(v[0]), "[]"),
			Port:     strings.TrimSpace(v[1]),
			Hostname: strings.TrimSpace(v[2]),
			SSL:      "nossl",
			Cert:     strings.TrimSpace(v[3]),
		}
		if ssl.State == 1 {
			nd.SSL = "ssl"
		}
		if err := de.checkDsn(nd); err != nil {
			return err
		}
		done(nd)
		return nil
	})
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
