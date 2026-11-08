package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
)

// dkimMaxSignatures caps the signatures verified in a message, each needs a
// DNS lookup
const dkimMaxSignatures = 5

// dkimLookupTimeout is how long the DNS lookup of a key may take
const dkimLookupTimeout = 10 * time.Second

// dkimLookupTXT looks up the DNS TXT records of DKIM keys
var dkimLookupTXT = func(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dkimLookupTimeout)
	defer cancel()
	return net.DefaultResolver.LookupTXT(ctx, domain)
}

// dkimVerify verifies the DKIM signatures of the message read from r. There
// is a result for each signature, or one "none" if there's no signature.
func dkimVerify(r io.Reader) []authres.Result {
	verifs, err := dkim.VerifyWithOptions(r, &dkim.VerifyOptions{
		LookupTXT:        dkimLookupTXT,
		MaxVerifications: dkimMaxSignatures,
	})
	if err != nil && err != dkim.ErrTooManySignatures {
		// the message can't be read or parsed
		return []authres.Result{&authres.DKIMResult{Value: authres.ResultPermError, Reason: dkimReason(err)}}
	}
	results := make([]authres.Result, 0, len(verifs))
	for _, v := range verifs {
		r := &authres.DKIMResult{Domain: v.Domain, Identifier: v.Identifier}
		switch {
		case v.Err == nil:
			r.Value = authres.ResultPass
		case dkim.IsTempFail(v.Err):
			r.Value = authres.ResultTempError
		case dkim.IsPermFail(v.Err):
			r.Value = authres.ResultPermError
		default:
			// the signature or the body hash don't match
			r.Value = authres.ResultFail
		}
		if v.Err != nil {
			r.Reason = dkimReason(v.Err)
		}
		results = append(results, r)
	}
	if len(results) == 0 {
		results = append(results, &authres.DKIMResult{Value: authres.ResultNone})
	}
	return results
}

func dkimReason(err error) string {
	return strings.TrimPrefix(err.Error(), "dkim: ")
}

// authResultsHeader returns an Authentication-Results header field of the
// results, by identity (our hostname), a result on each line. A passing
// signature is commented: (author) when of a From domain, else (third-party).
func authResultsHeader(identity string, results []authres.Result, fromDomains []string) string {
	h := "Authentication-Results: " + identity
	for _, r := range results {
		h += ";\r\n" + dkimIndent + formatResult(identity, r, dkimComment(r, fromDomains))
	}
	return h + "\r\n"
}

// dkimComment returns the comment of a DKIM result: how its passing
// signature relates to the From domains, "" for other results
func dkimComment(r authres.Result, fromDomains []string) string {
	res, ok := r.(*authres.DKIMResult)
	if !ok || res.Value != authres.ResultPass || len(fromDomains) == 0 {
		return ""
	}
	for _, from := range fromDomains {
		if dkimAuthorDomain(res.Domain, from) {
			return "author"
		}
	}
	return "third-party"
}

// formatResult formats a result as in Authentication-Results, with comment
// after the value if any: dkim=pass (author) header.d=...
func formatResult(identity string, r authres.Result, comment string) string {
	s := strings.TrimSpace(strings.TrimPrefix(authres.Format(identity, []authres.Result{r}), identity+";"))
	if comment == "" {
		return s
	}
	method, params, _ := strings.Cut(s, " ")
	return strings.TrimSpace(method + " (" + comment + ") " + params)
}

// stripAuthResults removes from the header block the Authentication-Results
// fields of one of ids, our hostnames (RFC 8601 section 5): ours are added,
// a forged one could tell a mail client that a check passed.
func stripAuthResults(header []byte, ids []string) (stripped []byte, removed int) {
	for _, field := range headerFields(header) {
		if authResultsOf(field, ids) {
			removed++
			continue
		}
		stripped = append(stripped, field...)
	}
	return stripped, removed
}

// headerFields splits a header block in fields, with their continuation
// lines; the blank line ending it is the last one
func headerFields(header []byte) [][]byte {
	var fields [][]byte
	for len(header) > 0 {
		end := 0
		for {
			i := bytes.IndexByte(header[end:], '\n')
			if i < 0 {
				end = len(header)
				break
			}
			end += i + 1
			// continued if the next line starts with a space, unless this
			// one is the blank line
			if end == len(header) || (header[end] != ' ' && header[end] != '\t') || bytes.Equal(header[:end], []byte("\r\n")) {
				break
			}
		}
		fields = append(fields, header[:end])
		header = header[end:]
	}
	return fields
}

// authResultsOf tells if field is an Authentication-Results of one of ids
func authResultsOf(field []byte, ids []string) bool {
	name, value, ok := strings.Cut(string(field), ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "Authentication-Results") {
		return false
	}
	// authserv-id [version] [comment]; results
	id, _, _ := strings.Cut(value, ";")
	words := strings.Fields(id)
	if len(words) == 0 {
		return false
	}
	for _, our := range ids {
		if our != "" && strings.EqualFold(words[0], our) {
			return true
		}
	}
	return false
}
