package core

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// DNSRecord is a DNS record cocosmail needs
type DNSRecord struct {
	// Name is the full name, without trailing dot; the IP address for PTR
	Name  string
	Type  string
	Value string
	// Note tells why the record is there or what to check, may be empty
	Note string
	// Optional: the setup works without it, Check doesn't count it missing
	Optional bool
	// Status is the result of Check, Found what's in DNS if it differs
	Status, Found string
	// spfIPs are the addresses an SPF record must allow
	spfIPs []string
}

// DNSExport is the DNS setup of a server, from its settings and data
type DNSExport struct {
	Records []DNSRecord
	// Zones are the domains of the server, the records are grouped by them
	Zones []string
	// Notes apply to the whole setup
	Notes []string
	// Checked: the records were looked up in DNS
	Checked bool
}

// dnsPublicIPv4 stands for the public address of the server when it's unknown
const dnsPublicIPv4 = "<public IPv4 of this server>"

// DNSHostIP returns the address of the server used to reach the internet,
// IPv6 or IPv4, nil if there's none. No packet is sent.
func DNSHostIP(v6 bool) net.IP {
	network, addr := "udp4", "8.8.8.8:53"
	if v6 {
		network, addr = "udp6", "[2001:4860:4860::8888]:53"
	}
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

// ExportDNS returns the DNS records of the server: MX of the domains, A and
// AAAA of the listeners and the HELO names of deliverd, PTR of the outgoing
// IPs, SPF, DKIM, DMARC, and SRV records for mail clients (RFC 6186, 8314).
// values are the settings. hostIP gives the address of the server for
// listeners and outgoing IPs on all addresses (0.0.0.0, ::).
func ExportDNS(values map[string]string, data *Data, hostIP func(v6 bool) net.IP) *DNSExport {
	b := &dnsBuilder{
		DNSExport: &DNSExport{},
		values:    values,
		data:      data,
		hostIP:    hostIP,
		seen:      map[string]bool{},
		hostAddrs: map[bool]string{},
	}
	b.build()
	return b.DNSExport
}

type dnsBuilder struct {
	*DNSExport
	values map[string]string
	data   *Data
	hostIP func(v6 bool) net.IP
	seen   map[string]bool
	// address of the server by family (true: IPv6), "-" when it has none
	hostAddrs map[bool]string
	listeners []dnsListener
	outgoing  []dnsOutgoing
}

type dnsListener struct {
	proto string
	port  int
	ssl   bool
	name  string
	addrs []string
}

// dnsOutgoing is an address deliverd sends from, with its HELO name
type dnsOutgoing struct {
	addr, name string
}

func (b *dnsBuilder) note(format string, a ...interface{}) {
	n := fmt.Sprintf(format, a...)
	for _, have := range b.Notes {
		if have == n {
			return
		}
	}
	b.Notes = append(b.Notes, n)
}

// add adds a record, returns it, nil if it's there already. The pointer is
// valid until the next add.
func (b *dnsBuilder) add(name, typ, value, note string) *DNSRecord {
	if typ != "PTR" {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
	}
	key := name + " " + typ + " " + value
	if b.seen[key] {
		return nil
	}
	b.seen[key] = true
	b.Records = append(b.Records, DNSRecord{Name: name, Type: typ, Value: value, Note: note})
	return &b.Records[len(b.Records)-1]
}

func (b *dnsBuilder) bool(key string) bool {
	v, _ := strconv.ParseBool(b.values[key])
	return v
}

// hostAddr returns the public address of the server, a placeholder if it's
// unknown, "" if it has no address of this family
func (b *dnsBuilder) hostAddr(v6 bool) string {
	if a, ok := b.hostAddrs[v6]; ok {
		if a == "-" {
			return ""
		}
		return a
	}
	a := "-"
	ip := b.hostIP(v6)
	switch {
	case ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate():
		a = ip.String()
	case !v6:
		// behind NAT, or no route: the user knows it. Without public IPv6,
		// no IPv6 records.
		a = dnsPublicIPv4
		if ip != nil {
			b.note("This server's IPv4 address %s is private: replace %s with the public address it's reached at, or use --public-ip.", ip, dnsPublicIPv4)
		} else {
			b.note("This server's IPv4 address is unknown: replace %s with it, or use --public-ip.", dnsPublicIPv4)
		}
	}
	b.hostAddrs[v6] = a
	if a == "-" {
		return ""
	}
	return a
}

// addrs returns the public addresses of ip: the server's when it's all
// addresses, none when it's loopback. dual: :: also means IPv4, as for
// listeners.
func (b *dnsBuilder) addrs(ip net.IP, dual bool) (addrs []string) {
	switch {
	case ip == nil || ip.IsUnspecified():
		if ip == nil || ip.To4() == nil {
			if a := b.hostAddr(true); a != "" {
				addrs = append(addrs, a)
			}
			if !dual && ip != nil {
				return
			}
		}
		if a := b.hostAddr(false); a != "" {
			addrs = append([]string{a}, addrs...)
		}
		return
	case ip.IsLoopback():
		return nil
	case ip.IsPrivate():
		b.note("%s is a private address: in A/AAAA records and SPF, replace it with the public address it's reached at.", ip)
	}
	return []string{ip.String()}
}

func dnsIsIPv6(addr string) bool {
	return strings.Contains(addr, ":")
}

func (b *dnsBuilder) addHost(name, addr string) {
	if dnsIsIPv6(addr) {
		b.add(name, "AAAA", addr, "")
	} else {
		b.add(name, "A", addr, "")
	}
}

func (b *dnsBuilder) build() {
	me := strings.ToLower(b.values["me"])
	b.readListeners()
	b.readOutgoing(me)

	local, relay, aliasOf := b.domains()
	sending := b.sendingDomains(local)
	b.Zones = dnsUnique(append(append(append(append([]string{}, local...), relay...), sortedKeys(aliasOf)...), sending...))

	// MX
	var mx []string
	for _, l := range b.listeners {
		if l.proto == "smtp" && l.port == 25 {
			mx = append(mx, l.name)
		}
	}
	mx = dnsUnique(mx)
	receiving := dnsUnique(append(append(append([]string{}, local...), relay...), sortedKeys(aliasOf)...))
	if len(mx) == 0 && len(receiving) > 0 {
		b.note("No SMTP listener on port 25 in %s: no MX records, mail can't be received from other servers.", SettingEnvName("smtpd_dsns"))
	}
	for _, d := range receiving {
		note := ""
		if contains(relay, d) {
			note = "relayed to another server, its SPF and DKIM are the ones of that server"
		} else if to, ok := aliasOf[d]; ok {
			note = "domain alias of " + to
		}
		for _, host := range dnsHostsFor(mx, d) {
			b.add(d, "MX", "10 "+host, note)
		}
	}

	// A and AAAA of the listeners and HELO names
	for _, l := range b.listeners {
		for _, a := range l.addrs {
			b.addHost(l.name, a)
		}
	}
	for _, o := range b.outgoing {
		b.addHost(o.name, o.addr)
	}

	b.addSPF(sending)
	b.addDKIM(sending)
	b.addDMARC(sending)
	b.addSRV(local)
	b.addPTR()
}

func (b *dnsBuilder) readListeners() {
	for _, p := range []struct{ proto, launch, dsns string }{
		{"smtp", "smtpd_launch", "smtpd_dsns"},
		{"imap", "imapd_launch", "imapd_dsns"},
		{"pop3", "pop3d_launch", "pop3d_dsns"},
	} {
		if !b.bool(p.launch) {
			continue
		}
		dsns, err := GetDsnsFromString(b.values[p.dsns])
		if err != nil {
			b.note("%s: %s", SettingEnvName(p.dsns), err)
			continue
		}
		for _, d := range dsns {
			addrs := b.addrs(d.TcpAddr.IP, true)
			if len(addrs) == 0 {
				// on loopback, not for other servers
				continue
			}
			b.listeners = append(b.listeners, dnsListener{
				proto: p.proto,
				port:  d.TcpAddr.Port,
				ssl:   d.Ssl,
				name:  strings.ToLower(d.SystemName),
				addrs: addrs,
			})
		}
	}
}

// readOutgoing reads the addresses of deliverd_local_ips and of the routes
func (b *dnsBuilder) readOutgoing(me string) {
	if !b.bool("deliverd_launch") {
		b.note("%s is off: no PTR and SPF records for outgoing mail.", SettingEnvName("deliverd_launch"))
		return
	}
	lists := []string{b.values["deliverd_local_ips"]}
	for _, r := range b.data.Routes {
		if r.LocalIPs != "" {
			lists = append(lists, r.LocalIPs)
		}
	}
	for _, list := range lists {
		for _, entry := range strings.FieldsFunc(list, func(r rune) bool { return r == '&' || r == '|' }) {
			ip, name, err := ParseIPAndName(entry)
			if err != nil {
				b.note("local IP %s: %s", entry, err)
				continue
			}
			if name == "" {
				name = me
			}
			for _, a := range b.addrs(ip, false) {
				o := dnsOutgoing{addr: a, name: strings.ToLower(name)}
				if !containsOutgoing(b.outgoing, o) {
					b.outgoing = append(b.outgoing, o)
				}
			}
		}
	}
}

func containsOutgoing(list []dnsOutgoing, o dnsOutgoing) bool {
	for _, have := range list {
		if have == o {
			return true
		}
	}
	return false
}

// domains returns the local domains, the relayed ones, and the domain
// aliases with the domain they're delivered to
func (b *dnsBuilder) domains() (local, relay []string, aliasOf map[string]string) {
	aliasOf = map[string]string{}
	for _, d := range b.data.Domains {
		if d.Local {
			local = append(local, strings.ToLower(d.Name))
		} else {
			relay = append(relay, strings.ToLower(d.Name))
		}
	}
	for _, a := range b.data.Aliases {
		if a.IsDomain() {
			aliasOf[strings.ToLower(a.Alias)] = strings.ToLower(strings.Join(a.DeliverTo, ", "))
		}
	}
	return dnsUnique(local), dnsUnique(relay), aliasOf
}

// sendingDomains returns the domains mail is sent from: local domains, of
// users and of DKIM keys
func (b *dnsBuilder) sendingDomains(local []string) []string {
	sending := append([]string{}, local...)
	for _, u := range b.data.Users {
		if _, d, ok := strings.Cut(u.Login, "@"); ok {
			sending = append(sending, strings.ToLower(d))
		}
	}
	for _, k := range b.data.Dkim {
		sending = append(sending, strings.ToLower(k.Domain))
	}
	return dnsUnique(sending)
}

func (b *dnsBuilder) addSPF(sending []string) {
	if len(b.outgoing) == 0 {
		return
	}
	var mechs, ips []string
	for _, o := range b.outgoing {
		if !dnsPlaceholder(o.addr) {
			ips = append(ips, o.addr)
		}
		if dnsIsIPv6(o.addr) {
			mechs = append(mechs, "ip6:"+o.addr)
		} else {
			mechs = append(mechs, "ip4:"+o.addr)
		}
	}
	spf := "v=spf1 " + strings.Join(dnsUnique(mechs), " ") + " -all"
	for _, d := range sending {
		if r := b.add(d, "TXT", spf, "SPF: ~all instead of -all if other servers also send mail of the domain"); r != nil {
			r.spfIPs = ips
		}
	}
	// bounces have no sender: their SPF is checked on the HELO name
	for _, o := range b.outgoing {
		if !contains(sending, o.name) {
			b.add(o.name, "TXT", "v=spf1 a -all", "SPF of the HELO name: bounces have no sender, their SPF is checked on it")
			for i := range b.Records {
				if r := &b.Records[i]; r.Name == o.name && r.Type == "TXT" && !dnsPlaceholder(o.addr) && !contains(r.spfIPs, o.addr) {
					r.spfIPs = append(r.spfIPs, o.addr)
				}
			}
		}
	}
}

func (b *dnsBuilder) addDKIM(sending []string) {
	keys := map[string]bool{}
	for _, k := range b.data.Dkim {
		if k.DNSName == "" {
			continue
		}
		keys[strings.ToLower(k.Domain)] = true
		b.add(k.DNSName, "TXT", k.DNSRecord, "DKIM public key")
	}
	// bounces are signed with the key of their From domain (me) or of the
	// HELO name, or of a parent domain, see dkimSignKey
	if len(b.outgoing) > 0 && b.bool("deliverd_dkim_sign") {
		names := []string{strings.ToLower(b.values["me"])}
		for _, o := range b.outgoing {
			names = append(names, o.name)
		}
		signed := false
		for _, name := range names {
			for d := name; strings.Contains(d, "."); _, d, _ = strings.Cut(d, ".") {
				signed = signed || keys[d]
			}
		}
		if !signed {
			b.note("Bounces aren't DKIM signed: no key for %s, the HELO names or their parent domains.", names[0])
		}
	}
	if len(keys) > 0 && !b.bool("deliverd_dkim_sign") {
		b.note("%s is off: mail isn't signed, the DKIM records aren't used yet.", SettingEnvName("deliverd_dkim_sign"))
	}
	for _, d := range sending {
		if !keys[d] && len(b.outgoing) > 0 {
			b.note("%s has no DKIM key: cocosmail dkim enable %s, then export again.", d, d)
		}
	}
}

func (b *dnsBuilder) addDMARC(sending []string) {
	for _, d := range sending {
		v := "v=DMARC1; p=none"
		note := "DMARC: none only reports; quarantine or reject once SPF and DKIM pass"
		rua := ""
		for _, local := range []string{"dmarc", "postmaster"} {
			if b.receives(local + "@" + d) {
				rua = local + "@" + d
				break
			}
		}
		if rua != "" {
			v += "; rua=mailto:" + rua
		} else {
			note += "; add rua=mailto:ADDRESS to get reports"
		}
		b.add("_dmarc."+d, "TXT", v, note)
	}
}

// receives tells if mail to addr is delivered here
func (b *dnsBuilder) receives(addr string) bool {
	_, domain, _ := strings.Cut(addr, "@")
	for _, u := range b.data.Users {
		if u.Mailbox && (strings.EqualFold(u.Login, addr) || (u.Catchall && strings.HasSuffix(strings.ToLower(u.Login), "@"+domain))) {
			return true
		}
	}
	for _, a := range b.data.Aliases {
		if strings.EqualFold(a.Alias, addr) {
			return true
		}
	}
	return false
}

// addSRV adds the records mail clients find the servers with
func (b *dnsBuilder) addSRV(local []string) {
	byService := map[string][]dnsListener{}
	var services []string
	for _, l := range b.listeners {
		service := ""
		switch {
		case l.proto == "smtp" && l.ssl:
			service = "_submissions._tcp"
		case l.proto == "smtp" && l.port != 25:
			service = "_submission._tcp"
		case l.proto == "imap" && l.ssl:
			service = "_imaps._tcp"
		case l.proto == "imap":
			service = "_imap._tcp"
		case l.proto == "pop3" && l.ssl:
			service = "_pop3s._tcp"
		case l.proto == "pop3":
			service = "_pop3._tcp"
		}
		if service == "" {
			continue
		}
		if _, ok := byService[service]; !ok {
			services = append(services, service)
		}
		byService[service] = append(byService[service], l)
	}
	for _, service := range services {
		var names []string
		for _, l := range byService[service] {
			names = append(names, l.name)
		}
		for _, d := range local {
			hosts := dnsHostsFor(dnsUnique(names), d)
			for _, l := range byService[service] {
				if contains(hosts, l.name) {
					if r := b.add(service+"."+d, "SRV", fmt.Sprintf("0 1 %d %s", l.port, l.name), "optional, for mail clients to find the server"); r != nil {
						r.Optional = true
					}
				}
			}
		}
	}
}

func (b *dnsBuilder) addPTR() {
	ptr := map[string]string{}
	var order []string
	set := func(addr, name string) {
		if have, ok := ptr[addr]; ok {
			if have != name {
				b.note("%s is used by %s and %s, it has one PTR record: %s, the HELO name.", addr, have, name, have)
			}
			return
		}
		ptr[addr] = name
		order = append(order, addr)
	}
	for _, o := range b.outgoing {
		set(o.addr, o.name)
	}
	for _, l := range b.listeners {
		if l.proto == "smtp" && l.port == 25 {
			for _, a := range l.addrs {
				set(a, l.name)
			}
		}
	}
	for _, a := range order {
		b.add(a, "PTR", ptr[a], "")
	}
}

// dnsHostsFor returns the hosts of domain d among hosts: the ones in d, all
// of them if there's none, as with several hostnames (multihome) each
// usually serves its domain
func dnsHostsFor(hosts []string, d string) []string {
	var in []string
	for _, h := range hosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			in = append(in, h)
		}
	}
	if len(in) == 0 {
		return hosts
	}
	return in
}

func dnsUnique(list []string) (out []string) {
	seen := map[string]bool{}
	for _, s := range list {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

// zoneOf returns the zone of name: the longest of zones it's in, "" if none
func zoneOf(name string, zones []string) string {
	zone := ""
	for _, z := range zones {
		if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(zone) {
			zone = z
		}
	}
	return zone
}

var dnsTypeOrder = map[string]int{"MX": 0, "A": 1, "AAAA": 2, "TXT": 3, "SRV": 4}

// dnsZone is a zone with its records, in the order they're written
type dnsZone struct {
	// name is "" for names in none of the zones of the server
	name    string
	records []DNSRecord
}

// byZone groups the records by zone, sorted, the PTR records apart
func (e *DNSExport) byZone() (zones []dnsZone, ptr []DNSRecord) {
	records := map[string][]DNSRecord{}
	for _, r := range e.Records {
		if r.Type == "PTR" {
			ptr = append(ptr, r)
			continue
		}
		z := zoneOf(r.Name, e.Zones)
		records[z] = append(records[z], r)
	}
	names := append([]string{}, e.Zones...)
	sort.Strings(names)
	for _, z := range append(names, "") {
		list := records[z]
		if len(list) == 0 {
			continue
		}
		sort.SliceStable(list, func(i, j int) bool {
			return dnsTypeOrder[list[i].Type] < dnsTypeOrder[list[j].Type]
		})
		zones = append(zones, dnsZone{name: z, records: list})
	}
	return zones, ptr
}

// relName returns name relative to zone, @ for the zone itself
func relName(name, zone string) string {
	if zone == "" {
		return name
	}
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

// Text formats the records to create them by hand in DNS panels, by zone.
// Once checked, each record starts with its status.
func (e *DNSExport) Text() string {
	var buf bytes.Buffer
	buf.WriteString("# DNS records for cocosmail, from its settings and data.\n" +
		"# Create them in the DNS panel of each zone. Names are relative to the zone,\n" +
		"# @ is the zone itself. MX: priority then host. SRV: priority, weight, port\n" +
		"# and host. TXT: the whole value, without quotes.\n")
	if e.Checked {
		buf.WriteString("# Checked with the DNS resolver of this server: a change can take the TTL\n" +
			"# of the old record to show, often an hour.\n")
	}
	for _, n := range e.Notes {
		buf.WriteString("#\n# " + n + "\n")
	}

	zones, ptr := e.byZone()
	for _, z := range zones {
		if z.name == "" {
			buf.WriteString("\nOther names (full names, in their own zones)\n")
		} else {
			buf.WriteString("\n" + z.name + "\n")
		}
		var rows []dnsRow
		for _, r := range z.records {
			rows = append(rows, e.row(r, r.Type, relName(r.Name, z.name), r.Value))
		}
		writeDNSRows(&buf, rows)
	}
	if len(ptr) > 0 {
		buf.WriteString("\nReverse DNS (PTR): set by the provider of each address, not in a zone.\n" +
			"Each must match the A or AAAA record of its name.\n")
		var rows []dnsRow
		for _, r := range ptr {
			rows = append(rows, e.row(r, r.Name, r.Value))
		}
		writeDNSRows(&buf, rows)
	}
	if e.Checked {
		counts := map[string]int{}
		for _, r := range e.Records {
			counts[r.Status]++
		}
		var parts []string
		for _, s := range []string{DNSOk, DNSMissing, DNSDifferent, DNSFillIn, DNSError, DNSOptional} {
			if counts[s] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
			}
		}
		buf.WriteString("\n" + strings.Join(parts, ", ") + "\n")
	}
	return buf.String()
}

// dnsRow is a line of records: cells in columns, a note line before it,
// what was found in DNS on a line after it
type dnsRow struct {
	cells       []string
	note, found string
}

func (e *DNSExport) row(r DNSRecord, cells ...string) dnsRow {
	if e.Checked {
		cells = append([]string{strings.ToUpper(r.Status)}, cells...)
		if r.Status == DNSOk || r.Status == DNSOptional {
			cells[0] = r.Status
		}
	}
	return dnsRow{cells: cells, note: r.Note, found: r.Found}
}

// writeDNSRows writes rows in aligned columns, but the last one. A note is
// written once for consecutive rows with it.
func writeDNSRows(buf *bytes.Buffer, rows []dnsRow) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0].cells)-1)
	for _, row := range rows {
		for i := range widths {
			if len(row.cells[i]) > widths[i] {
				widths[i] = len(row.cells[i])
			}
		}
	}
	lastNote := ""
	for _, row := range rows {
		if row.note != "" && row.note != lastNote {
			buf.WriteString("  # " + row.note + "\n")
		}
		lastNote = row.note
		buf.WriteString("  ")
		for i, w := range widths {
			fmt.Fprintf(buf, "%-*s  ", w, row.cells[i])
		}
		buf.WriteString(row.cells[len(row.cells)-1] + "\n")
		if row.found != "" {
			buf.WriteString("  " + strings.Repeat(" ", widths[0]+2) + "found: " + row.found + "\n")
		}
	}
}
