package plugin

import (
	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/cocosmail/yaegi"
	"github.com/traefik/yaegi/interp"
)

//
func initPlugin(s *core.SMTPServerSession) bool {
	yag := interp.New(interp.Options{})
	yag.Use(yaegi.Symbols)
	_, err := yag.EvalPath("d:\\work\\src\\Go-src\\stunndard\\cocosmail\\build\\scripts\\testplugin.go")
	if err != nil {
		return false
	}
	v, err := yag.Eval("testplugin.setup")
	if err != nil {
		return false
	}
	setup := v.Interface().(func() bool)
	if r := setup(); r == false {
		return false
	}

	s.Yags = append(s.Yags, yag)

	return true
}

func connectPlugin(s *core.SMTPServerSession) bool {

	v, err := s.Yags[0].Eval("testplugin.connect")
	if err != nil {
		return false
	}
	connect := v.Interface().(func(s *core.SMTPServerSession) bool)
	if r := connect(s); r == false {
		return false
	}

	return true
}

func RegisterPlugins() {
	core.RegisterSMTPdPlugin("init", initPlugin)
	core.RegisterSMTPdPlugin("connect", connectPlugin)

}
