package core

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/spf"
)

// DNSLookup are the lookups of a DNS check, as in *net.Resolver
type DNSLookup interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// statuses of a checked record
const (
	DNSOk        = "ok"
	DNSMissing   = "missing"
	DNSDifferent = "different"
	DNSError     = "error"
	// DNSFillIn: the record has a placeholder, the public IP is unknown
	DNSFillIn = "fill in"
	// DNSOptional: an optional record is missing
	DNSOptional = "optional"
)

// dnsCheckTimeout is how long a lookup may take
const dnsCheckTimeout = 10 * time.Second

// Check looks up the records in DNS, sets their Status and what was Found
// when it's not what's expected. It returns how many aren't ok.
func (e *DNSExport) Check(r DNSLookup) (problems int) {
	var wg sync.WaitGroup
	limit := make(chan struct{}, 8)
	for i := range e.Records {
		wg.Add(1)
		go func(rec *DNSRecord) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			ctx, cancel := context.WithTimeout(context.Background(), dnsCheckTimeout)
			defer cancel()
			rec.Status, rec.Found = checkDNSRecord(ctx, r, *rec)
			if rec.Optional && rec.Status == DNSMissing {
				rec.Status = DNSOptional
			}
		}(&e.Records[i])
	}
	wg.Wait()
	e.Checked = true
	for _, rec := range e.Records {
		if rec.Status != DNSOk && rec.Status != DNSOptional {
			problems++
		}
	}
	return problems
}

func dnsPlaceholder(s string) bool {
	return strings.Contains(s, "<")
}

// dnsLookupStatus is the status of a failed lookup: missing if there's no
// such record
func dnsLookupStatus(err error) (status, found string) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return DNSMissing, ""
	}
	return DNSError, err.Error()
}

func checkDNSRecord(ctx context.Context, r DNSLookup, rec DNSRecord) (status, found string) {
	if rec.Type == "PTR" && dnsPlaceholder(rec.Name) {
		return DNSFillIn, ""
	}
	switch rec.Type {
	case "A", "AAAA":
		addrs, err := r.LookupIPAddr(ctx, rec.Name)
		if err != nil {
			status, found = dnsLookupStatus(err)
			if dnsPlaceholder(rec.Value) && status == DNSMissing {
				return DNSFillIn, ""
			}
			return status, found
		}
		var have []string
		for _, a := range addrs {
			if (a.IP.To4() == nil) == (rec.Type == "AAAA") {
				have = append(have, a.IP.String())
			}
		}
		return dnsCompare(rec.Value, have, func(want, have string) bool {
			return net.ParseIP(want).Equal(net.ParseIP(have))
		})

	case "MX":
		mxs, err := r.LookupMX(ctx, rec.Name)
		if err != nil {
			return dnsLookupStatus(err)
		}
		var have []string
		for _, mx := range mxs {
			have = append(have, strconv.Itoa(int(mx.Pref))+" "+dnsHost(mx.Host))
		}
		return dnsCompare(rec.Value, have, strings.EqualFold)

	case "SRV":
		_, srvs, err := r.LookupSRV(ctx, "", "", rec.Name)
		if err != nil {
			return dnsLookupStatus(err)
		}
		var have []string
		for _, s := range srvs {
			have = append(have, strconv.Itoa(int(s.Priority))+" "+strconv.Itoa(int(s.Weight))+" "+
				strconv.Itoa(int(s.Port))+" "+dnsHost(s.Target))
		}
		// priority and weight are the user's choice: port and host only
		return dnsCompare(rec.Value, have, func(want, have string) bool {
			w, h := strings.Fields(want), strings.Fields(have)
			return len(w) == 4 && len(h) == 4 && w[2] == h[2] && strings.EqualFold(w[3], h[3])
		})

	case "PTR":
		names, err := r.LookupAddr(ctx, rec.Name)
		if err != nil {
			return dnsLookupStatus(err)
		}
		var have []string
		for _, n := range names {
			have = append(have, dnsHost(n))
		}
		return dnsCompare(rec.Value, have, strings.EqualFold)

	case "TXT":
		txts, err := r.LookupTXT(ctx, rec.Name)
		if err != nil {
			return dnsLookupStatus(err)
		}
		status, found = checkTXT(rec.Value, txts)
		if status == DNSDifferent && len(rec.spfIPs) > 0 && !strings.Contains(found, "only one is allowed") {
			return checkSPF(ctx, r, rec, found)
		}
		return status, found
	}
	return DNSError, "unknown record type " + rec.Type
}

// dnsCompare: ok if one of have is want, else different, missing if have
// is empty
func dnsCompare(want string, have []string, same func(want, have string) bool) (status, found string) {
	if len(have) == 0 {
		if dnsPlaceholder(want) {
			return DNSFillIn, ""
		}
		return DNSMissing, ""
	}
	for _, h := range have {
		if same(want, h) {
			return DNSOk, ""
		}
	}
	if dnsPlaceholder(want) {
		return DNSFillIn, strings.Join(have, ", ")
	}
	return DNSDifferent, strings.Join(have, ", ")
}

func dnsHost(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// checkTXT compares the SPF, DKIM or DMARC record want with the TXT
// records of its name
func checkTXT(want string, txts []string) (status, found string) {
	kind := strings.ToLower(strings.SplitN(strings.SplitN(want, ";", 2)[0], " ", 2)[0])
	var same []string
	for _, t := range txts {
		v := strings.ToLower(strings.SplitN(strings.SplitN(strings.TrimSpace(t), ";", 2)[0], " ", 2)[0])
		// v=DKIM1 is optional in DKIM records
		if strings.ReplaceAll(v, " ", "") == kind || (kind == "v=dkim1" && dkimTag(t, "p") != "") {
			same = append(same, t)
		}
	}
	switch {
	case len(same) == 0:
		if dnsPlaceholder(want) {
			return DNSFillIn, ""
		}
		return DNSMissing, ""
	case len(same) > 1 && kind != "v=dkim1":
		// RFC 7208 3.2, RFC 7489 6.6.3: none is used
		return DNSDifferent, strconv.Itoa(len(same)) + " records, only one is allowed: " + strings.Join(same, " | ")
	}
	have := same[0]
	switch kind {
	case "v=spf1":
		if strings.Join(strings.Fields(strings.ToLower(have)), " ") == strings.Join(strings.Fields(strings.ToLower(want)), " ") {
			return DNSOk, ""
		}
	case "v=dkim1":
		// the key matters, the other tags have defaults
		for _, h := range same {
			if dkimTag(h, "p") == dkimTag(want, "p") {
				return DNSOk, ""
			}
		}
	case "v=dmarc1":
		// any policy will do, a stricter one is the next step: shown
		if have != want {
			return DNSOk, have
		}
		return DNSOk, ""
	default:
		if have == want {
			return DNSOk, ""
		}
	}
	if dnsPlaceholder(want) {
		return DNSFillIn, have
	}
	return DNSDifferent, have
}

// dkimTag returns the value of tag in a DKIM record, without spaces
func dkimTag(record, tag string) string {
	for _, t := range strings.Split(record, ";") {
		name, value, ok := strings.Cut(t, "=")
		if ok && strings.TrimSpace(name) == tag {
			return strings.Join(strings.Fields(value), "")
		}
	}
	return ""
}

// checkSPF evaluates the SPF record found for the name of rec, that isn't
// the one expected: ok if it allows each address of rec, as v=spf1 mx -all
// can
func checkSPF(ctx context.Context, r DNSLookup, rec DNSRecord, found string) (status, result string) {
	var failed []string
	for _, a := range rec.spfIPs {
		res, err := spf.CheckHostWithSender(net.ParseIP(a), rec.Name, "postmaster@"+rec.Name,
			spf.WithResolver(r), spf.WithContext(ctx))
		if res != spf.Pass {
			f := a + ": " + string(res)
			if err != nil && (res == spf.TempError || res == spf.PermError) {
				f += " (" + err.Error() + ")"
			}
			failed = append(failed, f)
		}
	}
	if len(failed) > 0 {
		return DNSDifferent, found + "; " + strings.Join(failed, ", ")
	}
	return DNSOk, found + " (allows the same addresses)"
}
