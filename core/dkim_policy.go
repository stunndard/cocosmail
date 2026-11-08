package core

import (
	"io"
	"mime"
	"net/mail"
	"regexp"
	"strings"

	"github.com/emersion/go-msgauth/authres"
)

// the result of the DKIM check of a message, from its signatures
const (
	dkimNone      = "none"      // no signature
	dkimAuthor    = "author"    // a valid signature of the From domain
	dkimPass      = "pass"      // valid signatures of other domains only
	dkimFail      = "fail"      // the message changed since it was signed
	dkimTempError = "temperror" // a key couldn't be looked up, for now
	dkimPermError = "permerror" // no key, a bad signature or key
)

// dkimActionResults are the results in the order of smtpd_dkim_action
var dkimActionResults = []string{dkimNone, dkimAuthor, dkimPass, dkimFail, dkimTempError, dkimPermError}

// dkimOutcome sums up the results of the signatures. author needs each From
// domain signed. A key unavailable for now wins over the other results: its
// signature could be the one of the author.
func dkimOutcome(results []authres.Result, fromDomains []string) string {
	var pass, fail, temp, perm bool
	signed := make(map[string]bool)
	for _, r := range results {
		res, ok := r.(*authres.DKIMResult)
		if !ok {
			continue
		}
		switch res.Value {
		case authres.ResultPass:
			pass = true
			for _, from := range fromDomains {
				if dkimAuthorDomain(res.Domain, from) {
					signed[from] = true
				}
			}
		case authres.ResultFail:
			fail = true
		case authres.ResultTempError:
			temp = true
		case authres.ResultPermError:
			perm = true
		}
	}
	switch {
	case len(fromDomains) > 0 && len(signed) == len(fromDomains):
		return dkimAuthor
	case temp:
		return dkimTempError
	case pass:
		return dkimPass
	case fail:
		return dkimFail
	case perm:
		return dkimPermError
	}
	return dkimNone
}

// dkimAuthorDomain tells if a signature of domain d is one of the author of
// mail from domain from: from is d or a subdomain of it. No one can sign for
// a public suffix (co.uk), its DNS has no keys.
func dkimAuthorDomain(d, from string) bool {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	return d != "" && (from == d || strings.HasSuffix(from, "."+d))
}

// replies refusing a message for its DKIM result, as for SPF: the sender
// isn't told why, the log is
const (
	dkimRejectReply     = "5.5.1 Sorry, no mailbox here by that name"
	dkimTempRejectReply = "4.3.0 Oops, problem with relay access"
)

// dkimRejection returns the reply refusing the message for its DKIM result,
// code 0 to accept it
func dkimRejection(outcome string, fromDomains []string) (code uint32, msg string) {
	reject := false
	if outcome != dkimAuthor && dkimProtected(fromDomains, splitDomains(Cfg.GetSmtpdDkimRequireAuthor())) {
		// domains that must sign their mail
		reject = true
	} else {
		actions := strings.Split(Cfg.GetSmtpdDkimAction(), ":")
		for i, r := range dkimActionResults {
			if r == outcome && i < len(actions) && actions[i] == "reject" {
				reject = true
			}
		}
	}
	switch {
	case !reject:
		return 0, ""
	case outcome == dkimTempError:
		// the key may be found later
		return 451, dkimTempRejectReply
	}
	return 550, dkimRejectReply
}

// dkimProtected tells if one of the From domains is one of domains or a
// subdomain of it
func dkimProtected(fromDomains, domains []string) bool {
	for _, from := range fromDomains {
		for _, d := range domains {
			if dkimAuthorDomain(d, from) {
				return true
			}
		}
	}
	return false
}

// any charset is read as is: only the addresses are needed
var fromParser = mail.AddressParser{WordDecoder: &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) { return input, nil },
}}

// what looks like the domain of an address, when From can't be parsed
var fromDomainRe = regexp.MustCompile(`@\s*([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)`)

// fromDomains returns the domains of the addresses in the From fields of the
// header block, lowercased, each once
func fromDomains(header []byte) []string {
	var domains []string
	seen := make(map[string]bool)
	add := func(d string) {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	for _, field := range headerFields(header) {
		name, value, ok := strings.Cut(string(field), ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "From") {
			continue
		}
		value = strings.NewReplacer("\r\n", "", "\n", "").Replace(value)
		addrs, err := fromParser.ParseList(value)
		if err != nil {
			// a mail client may show what the parser refuses: the domains
			// it finds must not escape the checks
			for _, m := range fromDomainRe.FindAllStringSubmatch(value, -1) {
				add(m[1])
			}
			continue
		}
		for _, a := range addrs {
			if i := strings.LastIndexByte(a.Address, '@'); i >= 0 {
				add(a.Address[i+1:])
			}
		}
	}
	return domains
}
