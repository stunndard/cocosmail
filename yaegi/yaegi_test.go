package yaegi

import (
	"testing"

	"github.com/traefik/yaegi/interp"
)

// a plugin using the session API: these symbols must be extracted, else
// plugins fail to load. If this fails, run go generate ./yaegi.
const testPlugin = `package rawcheck

import (
	"bufio"
	"io"
	"strings"

	"github.com/stunndard/cocosmail/core"
)

func data(s *core.SMTPServerSession) (bool, bool, error) {
	r, err := s.RawMail()
	if err != nil {
		return false, false, err
	}
	defer r.Close()
	if _, err := io.Copy(io.Discard, r); err != nil {
		return false, false, err
	}
	return false, false, nil
}

func beforequeue(s *core.SMTPServerSession) (bool, bool, error) {
	r, err := s.RawMail()
	if err != nil {
		return false, false, err
	}
	defer r.Close()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "Subject:") {
			s.Log(sc.Text())
		}
	}
	_, err = core.QueueAddReader(r, "id", s.Envelope, "")
	return false, false, err
}
`

func TestPluginSymbols(t *testing.T) {
	yag := interp.New(interp.Options{})
	yag.Use(Symbols)
	if _, err := yag.Eval(testPlugin); err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"data", "beforequeue"} {
		if _, err := yag.Eval("rawcheck." + hook); err != nil {
			t.Fatal(err)
		}
	}
}
