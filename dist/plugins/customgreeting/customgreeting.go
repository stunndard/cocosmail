package customgreeting

import (
	"github.com/stunndard/cocosmail/core"
)

var counter = "0000"

func initialize() error {

	counter = "1111"
	return nil
}

func connect(s *core.SMTPServerSession) (bool, bool, error) {
	s.Out("220 hi from customgreeting plugin " + counter)
	return true, false, nil
}

func helo(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func mailpre(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func mailpost(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func rcptto(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func data(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func beforequeue(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func quit(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func exitasap(s *core.SMTPServerSession) (done, drop bool, err error) {
	return false, false, nil
}

func notify(s *core.SMTPServerSession) (drop bool, err error) {
	return false, nil
}
