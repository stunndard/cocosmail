package tui

import (
	"errors"
	"net"
	"strings"

	"github.com/stunndard/cocosmail/core"
	"github.com/unxed/vtinput"
	"github.com/unxed/vtui"
)

// localIP is a local address for outgoing mail, with its HELO hostname
type localIP struct {
	IP       string
	Hostname string // "": COCOSMAIL_ME
}

// String returns the entry as in deliverd_local_ips: IP or IP:hostname,
// IPv6 in brackets when followed by a hostname
func (l localIP) String() string {
	if l.Hostname == "" {
		return l.IP
	}
	if strings.Contains(l.IP, ":") {
		return "[" + l.IP + "]:" + l.Hostname
	}
	return l.IP + ":" + l.Hostname
}

// parseLocalIps splits deliverd_local_ips in entries, roundRobin is true
// when they're separated by |, else by & (failover)
func parseLocalIps(value string) (ips []localIP, roundRobin bool) {
	roundRobin = strings.Contains(value, "|")
	for _, s := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == '|' }) {
		ip, name, err := core.ParseIPAndName(s)
		if err != nil {
			// shown as is, fixed when edited
			ips = append(ips, localIP{IP: strings.TrimSpace(s)})
			continue
		}
		ips = append(ips, localIP{IP: ip.String(), Hostname: name})
	}
	return
}

// LocalIpsEditor edits deliverd_local_ips, one address per row, and the mode:
// failover (&) or round robin (|)
type LocalIpsEditor struct {
	*listEditor[localIP]
	roundRobin bool
}

// newLocalIpsEditor returns the editor of deliverd_local_ips, over ed
func newLocalIpsEditor(ed *Editor) *LocalIpsEditor {
	le := &LocalIpsEditor{}
	le.listEditor = newListEditor[localIP](ed, "deliverd_local_ips", "local IP", "local IPs", []vtui.TableColumn{
		{Title: "Local IP address", Width: 0, MinWidth: 16},
		{Title: "HELO hostname", Width: 0, MinWidth: 16},
	})
	le.items, le.roundRobin = parseLocalIps(ed.values["deliverd_local_ips"])
	le.value = func(ips []localIP) string {
		parts := make([]string, len(ips))
		for i, ip := range ips {
			parts[i] = ip.String()
		}
		sep := "&"
		if le.roundRobin {
			sep = "|"
		}
		return strings.Join(parts, sep)
	}
	le.cell = func(ip localIP, col int) string {
		if col == 0 {
			switch ip.IP {
			case "0.0.0.0":
				return ip.IP + " (any IPv4)"
			case "::":
				return ip.IP + " (any IPv6)"
			}
			return ip.IP
		}
		if ip.Hostname == "" {
			return "(" + le.ed.values["me"] + ")"
		}
		return ip.Hostname
	}
	le.newItem = func() localIP { return localIP{IP: "0.0.0.0"} }
	le.dialog = le.rowDialog
	le.check = func(ips []localIP) error {
		if len(ips) == 0 {
			return errors.New("at least one local IP is needed to send mail")
		}
		return nil
	}
	le.titleSuffix = func() string {
		if le.roundRobin {
			return "round robin"
		}
		return "failover"
	}
	le.helpText = func() string {
		mode := "Failover (&): the addresses are tried in order, Ctrl+Up/Down moves them. F3: round robin."
		if le.roundRobin {
			mode = "Round robin (|): an address is picked at random for each delivery. F3: failover."
		}
		return mode + " IPv4 addresses send to IPv4 servers, IPv6 ones to IPv6 servers."
	}
	le.extraKey = func(e *vtinput.InputEvent) bool {
		if e.VirtualKeyCode != vtinput.VK_F3 {
			return false
		}
		le.roundRobin = !le.roundRobin
		le.refresh()
		return true
	}
	le.extraLabels = map[int][2]string{3: {"Mode", "Mode"}}
	le.extraHelp = [][2]string{{"F3", "Switch between failover (&) and round robin (|)"}}
	le.refresh()
	return le
}

// rowDialog returns the dialog editing one address, done is called with it on Ok
func (le *LocalIpsEditor) rowDialog(ip localIP, isNew bool, done func(localIP)) *vtui.Window {
	title := " Local IP "
	if isNew {
		title = " New local IP "
	}
	return le.itemDialog(title, []itemField{
		{label: "&IP address", value: ip.IP, hint: "0.0.0.0: any local IPv4, :: any local IPv6"},
		{label: "&Hostname", value: ip.Hostname, hint: "HELO name, empty: " + le.ed.values["me"]},
	}, nil, func(v []string, _ []bool) error {
		nip := localIP{IP: strings.Trim(strings.TrimSpace(v[0]), "[]"), Hostname: strings.TrimSpace(v[1])}
		parsed := net.ParseIP(nip.IP)
		if parsed == nil {
			return errors.New(nip.IP + " is not an IP address")
		}
		nip.IP = parsed.String()
		if strings.ContainsAny(nip.Hostname, ":;&| ") {
			return errors.New("the hostname can't contain : ; & | or spaces")
		}
		done(nip)
		return nil
	})
}
