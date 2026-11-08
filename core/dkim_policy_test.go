package core

import (
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/authres"
	"github.com/stretchr/testify/assert"
)

func TestFromDomains(t *testing.T) {
	for header, want := range map[string][]string{
		"From: Alice <alice@Mail.Example.COM>\r\nSubject: hi\r\n\r\n":                         {"mail.example.com"},
		"Subject: hi\r\nFrom: a@one.example, \"B, b\" <b@two.example>, c@one.example\r\n\r\n": {"one.example", "two.example"},
		"From: a@one.example\r\nfrom: b@two.example\r\n\r\n":                                  {"one.example", "two.example"},
		"From: Alice\r\n <alice@folded.example>\r\n\r\n":                                      {"folded.example"},
		// a charset the decoder doesn't know
		"From: =?koi8-r?B?8NLJ18XU?= <a@bank.example>\r\n\r\n": {"bank.example"},
		// refused by the parser, shown by some mail clients
		"From: <<a@bank.example>\r\n\r\n":        {"bank.example"},
		"From: x@bank.example.\r\n\r\n":          {"bank.example"},
		"Subject: no from\r\n\r\n":               nil,
		"From: undisclosed-recipients:;\r\n\r\n": nil,
	} {
		assert.Equal(t, want, fromDomains([]byte(header)), header)
	}
}

func TestDkimAuthorDomain(t *testing.T) {
	assert.True(t, dkimAuthorDomain("example.com", "example.com"))
	assert.True(t, dkimAuthorDomain("Example.com.", "mail.example.com"))
	assert.False(t, dkimAuthorDomain("mail.example.com", "example.com"))
	assert.False(t, dkimAuthorDomain("ample.com", "example.com"))
	assert.False(t, dkimAuthorDomain("example.com", "example.com.evil.net"))
	assert.False(t, dkimAuthorDomain("", "example.com"))
}

func dkimRes(value authres.ResultValue, domain string) authres.Result {
	return &authres.DKIMResult{Value: value, Domain: domain}
}

func TestDkimOutcome(t *testing.T) {
	from := []string{"example.com"}
	none := []authres.Result{dkimRes(authres.ResultNone, "")}
	assert.Equal(t, dkimNone, dkimOutcome(none, from))
	assert.Equal(t, dkimAuthor, dkimOutcome([]authres.Result{dkimRes(authres.ResultPass, "example.com")}, []string{"mail.example.com"}))
	assert.Equal(t, dkimPass, dkimOutcome([]authres.Result{dkimRes(authres.ResultPass, "esp.example")}, from))
	// no From: no author
	assert.Equal(t, dkimPass, dkimOutcome([]authres.Result{dkimRes(authres.ResultPass, "example.com")}, nil))
	// a broken signature doesn't matter when another one is of the author
	assert.Equal(t, dkimAuthor, dkimOutcome([]authres.Result{dkimRes(authres.ResultFail, "example.com"), dkimRes(authres.ResultPass, "example.com")}, from))
	// the key that couldn't be looked up may be the author's
	assert.Equal(t, dkimTempError, dkimOutcome([]authres.Result{dkimRes(authres.ResultPass, "esp.example"), dkimRes(authres.ResultTempError, "example.com")}, from))
	assert.Equal(t, dkimFail, dkimOutcome([]authres.Result{dkimRes(authres.ResultPermError, "x.example"), dkimRes(authres.ResultFail, "example.com")}, from))
	assert.Equal(t, dkimPermError, dkimOutcome([]authres.Result{dkimRes(authres.ResultPermError, "example.com")}, from))
	// each From domain signed
	two := []string{"example.com", "other.example"}
	assert.Equal(t, dkimPass, dkimOutcome([]authres.Result{dkimRes(authres.ResultPass, "example.com")}, two))
	assert.Equal(t, dkimAuthor, dkimOutcome([]authres.Result{dkimRes(authres.ResultPass, "example.com"), dkimRes(authres.ResultPass, "other.example")}, two))
}

func dkimTestConfig(t *testing.T, action, requireAuthor string) {
	old := Cfg
	t.Cleanup(func() { Cfg = old })
	Cfg = &Config{}
	Cfg.cfg.SmtpdDkimAction = action
	Cfg.cfg.SmtpdDkimRequireAuthor = requireAuthor
}

func TestDkimRejection(t *testing.T) {
	from := []string{"example.com"}
	dkimTestConfig(t, "accept:accept:accept:accept:accept:accept", "")
	for _, r := range dkimActionResults {
		code, _ := dkimRejection(r, from)
		assert.Equal(t, uint32(0), code, r)
	}

	dkimTestConfig(t, "reject:accept:reject:reject:reject:reject", "")
	for _, r := range dkimActionResults {
		code, msg := dkimRejection(r, from)
		switch r {
		case dkimAuthor:
			assert.Equal(t, uint32(0), code)
		case dkimTempError:
			assert.Equal(t, uint32(451), code)
			assert.Equal(t, dkimTempRejectReply, msg)
		default:
			// the sender isn't told why
			assert.Equal(t, uint32(550), code, r)
			assert.Equal(t, dkimRejectReply, msg, r)
		}
	}

	// protected domains must be signed by themselves, whatever the actions
	dkimTestConfig(t, "accept:accept:accept:accept:accept:accept", "bank.example; Example.ORG")
	code, msg := dkimRejection(dkimPass, []string{"login.bank.example"})
	assert.Equal(t, uint32(550), code)
	assert.Equal(t, dkimRejectReply, msg)
	code, _ = dkimRejection(dkimNone, []string{"example.org"})
	assert.Equal(t, uint32(550), code)
	code, _ = dkimRejection(dkimTempError, []string{"bank.example"})
	assert.Equal(t, uint32(451), code)
	code, _ = dkimRejection(dkimAuthor, []string{"bank.example"})
	assert.Equal(t, uint32(0), code)
	code, _ = dkimRejection(dkimNone, []string{"other.example", "notbank.example"})
	assert.Equal(t, uint32(0), code)
}

func TestValidateDkimSettings(t *testing.T) {
	assert.NoError(t, validateDkimAction("accept:accept:reject:reject:reject:accept"))
	assert.Error(t, validateDkimAction("accept:accept:accept:accept:accept"))
	assert.Error(t, validateDkimAction("accept:accept:accept:accept:accept:drop"))
	assert.NoError(t, validateDomains(""))
	assert.NoError(t, validateDomains("bank.example; Example.ORG;"))
	assert.Error(t, validateDomains("bank example"))
	assert.Error(t, validateDomains("[192.0.2.1]"))
	assert.Equal(t, []string{"bank.example", "example.org"}, splitDomains(" bank.example;;Example.ORG "))
}

// a message signed by its From domain is of the author, a message of
// another domain signed by it only passes
func TestDkimAuthorSigned(t *testing.T) {
	dkc := dkimTestKey(t)
	signed := dkimSign(t, dkc, dkimTestMessage)
	header := signed[:strings.Index(signed, "\r\n\r\n")+4]
	results := dkimVerify(strings.NewReader(signed))
	assert.Equal(t, dkimAuthor, dkimOutcome(results, fromDomains([]byte(header))))

	other := dkimSign(t, dkc, strings.Replace(dkimTestMessage, "alice@example.com", "alice@bank.example", 1))
	header = other[:strings.Index(other, "\r\n\r\n")+4]
	results = dkimVerify(strings.NewReader(other))
	assert.Equal(t, dkimPass, dkimOutcome(results, fromDomains([]byte(header))))
}
