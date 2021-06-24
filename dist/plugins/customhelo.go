package ban

import (
	"github.com/stunndard/cocosmail/core"
)

var counter = "0000"

func initialize() error {

	counter = "1111"
	return nil
}

func connect(s *core.SMTPServerSession) (bool, bool, error) {

	s.Out("220 hi from customhelo plugin " + counter)
	return true, false, nil
}
