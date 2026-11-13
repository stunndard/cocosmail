package core

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// dnsZoneTTL is the TTL of the records of zone files
const dnsZoneTTL = 3600

// ZoneFiles formats the records as zone files (RFC 1035), to import into DNS
// providers, by zone name, in names order. Records with a placeholder are
// commented out. Names in none of the zones of the server go to the zone of
// their parent domain.
func (e *DNSExport) ZoneFiles() (names []string, files map[string]string) {
	files = map[string]string{}
	zones, _ := e.byZone()
	var other []dnsZone
	for _, z := range zones {
		if z.name != "" {
			other = append(other, z)
			continue
		}
		byParent := map[string]int{}
		for _, r := range z.records {
			parent := r.Name
			if _, p, ok := strings.Cut(r.Name, "."); ok && strings.Contains(p, ".") {
				parent = p
			}
			i, ok := byParent[parent]
			if !ok {
				i = len(other)
				byParent[parent] = i
				other = append(other, dnsZone{name: parent})
			}
			other[i].records = append(other[i].records, r)
		}
	}
	for _, z := range other {
		names = append(names, z.name)
		files[z.name] = e.zoneFile(z)
	}
	return names, files
}

func (e *DNSExport) zoneFile(z dnsZone) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "; %s: records for cocosmail, from cocosmail config export-dns\n", z.name)
	for _, n := range e.Notes {
		buf.WriteString("; " + n + "\n")
	}
	fmt.Fprintf(&buf, "$ORIGIN %s.\n$TTL %d\n", z.name, dnsZoneTTL)
	width := 1
	for _, r := range z.records {
		if n := len(relName(r.Name, z.name)); n > width {
			width = n
		}
	}
	lastNote := ""
	for _, r := range z.records {
		note := r.Note
		comment := ""
		if dnsPlaceholder(r.Value) {
			note = "fill in the address, then remove the ; of the record"
			comment = "; "
		}
		if note != "" && note != lastNote {
			buf.WriteString("; " + note + "\n")
		}
		lastNote = note
		fmt.Fprintf(&buf, "%s%-*s  IN  %-4s  %s\n", comment, width, relName(r.Name, z.name), r.Type, zoneValue(r))
	}
	return buf.String()
}

// zoneValue returns the value of r as in zone files: full names end with a
// dot, TXT values are quoted, in strings of at most 255 bytes
func zoneValue(r DNSRecord) string {
	switch r.Type {
	case "MX", "SRV":
		f := strings.Fields(r.Value)
		if len(f) > 0 {
			f[len(f)-1] += "."
		}
		return strings.Join(f, " ")
	case "TXT":
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(r.Value)
		var parts []string
		for len(v) > 255 {
			// don't split an escape
			n := 255
			for n > 0 && v[n-1] == '\\' {
				n--
			}
			parts = append(parts, `"`+v[:n]+`"`)
			v = v[n:]
		}
		return strings.Join(append(parts, `"`+v+`"`), " ")
	}
	return r.Value
}

// ReverseText returns the PTR records, to set at the provider of each
// address, with the name of the reverse zone record, "" if there are none
func (e *DNSExport) ReverseText() string {
	_, ptr := e.byZone()
	if len(ptr) == 0 {
		return ""
	}
	var buf bytes.Buffer
	buf.WriteString("; Reverse DNS (PTR): set by the provider of each address, often in its\n" +
		"; control panel. Each must match the A or AAAA record of its name.\n")
	for _, r := range ptr {
		name := reverseName(r.Name)
		if name == "" {
			name = r.Name
		}
		fmt.Fprintf(&buf, "; %s  IN  PTR  %s.\n", name, r.Value)
	}
	return buf.String()
}

// reverseName returns the in-addr.arpa or ip6.arpa name of ip, "" if it's
// not an IP address
func reverseName(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ""
	}
	if v4 := addr.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	var b strings.Builder
	for i := len(addr) - 1; i >= 0; i-- {
		b.WriteString(strconv.FormatInt(int64(addr[i]&0xf), 16) + ".")
		b.WriteString(strconv.FormatInt(int64(addr[i]>>4), 16) + ".")
	}
	return b.String() + "ip6.arpa."
}
