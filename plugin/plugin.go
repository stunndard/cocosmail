package plugin

import (
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/cocosmail/yaegi"
	"github.com/traefik/yaegi/interp"
)

func InitModule() {
	core.InitSMTPdPlugins = InitSMTPdPlugins
	core.ExecSMTPdPlugins = ExecSMTPdPlugins
	core.AuthSMTPdPlugins = AuthSMTPdPlugins
}

func getActivePlugins() (cor []string, smtpd []string, deliveryd []string) {
	yag := interp.New(interp.Options{})
	_, err := yag.EvalPath(filepath.Join(core.Cfg.GetPluginPath(), "config.go"))
	if err != nil {
		return
	}
	sections := []string{
		"core",
		"smtpd",
		"deliveryd",
	}
	plugins := make(map[string][]string)
	var v reflect.Value
	for _, section := range sections {
		v, err = yag.Eval("config." + section)
		if err != nil {
			continue
		}
		config := v.Interface().(func() []string)
		plugins[section] = config()
	}
	cor = plugins["core"]
	smtpd = plugins["smtpd"]
	deliveryd = plugins["deliveryd"]
	return
}

//
func InitSMTPdPlugins(s *core.SMTPServerSession) {
	_, smtpdPlugins, _ := getActivePlugins()
	if len(smtpdPlugins) == 0 {
		s.LogDebug("no plugin configured to load")
		return
	}

	// load all plugins and execute init function
	for _, plugin := range smtpdPlugins {
		yag := interp.New(interp.Options{})
		yag.Use(yaegi.Symbols)
		_, err := yag.EvalPath(filepath.Join(core.Cfg.GetPluginPath(), plugin+".go"))
		if err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s failed to load: %s", plugin, err))
			continue
		}

		v, err := yag.Eval(plugin + ".initialize")
		if err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s failed to initialize: %s", plugin, err))
			continue
		}
		init := v.Interface().(func() error)
		if err := init(); err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s failed to initialize: %s", plugin, err))
			continue
		}

		s.YagPlugins = append(s.YagPlugins, core.YagPlugin{
			Yag:  yag,
			Name: plugin,
		})
		s.LogDebug(fmt.Sprintf("plugin %s initialized", plugin))
	}
	return
}

//
func ExecSMTPdPlugins(hook string, s *core.SMTPServerSession) (bool, bool) {
	var allDone bool
	for _, yag := range s.YagPlugins {
		v, err := yag.Yag.Eval(yag.Name + "." + hook)
		if err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s failed to Eval in %s: %s", yag.Name, hook, err))
			continue
		}
		hookFunc, ok := v.Interface().(func(s *core.SMTPServerSession) (bool, bool, error))
		if !ok {
			s.LogDebug(fmt.Sprintf("plugin %s hook %s is wrong type", yag.Name, hook))
			continue
		}
		done, drop, err := hookFunc(s)
		if err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s returned error in hook %s: %s", yag.Name, hook, err))
			continue
		}
		allDone = done
		// if at least one plugin returns drop, exit to host right away
		if drop {
			return false, true
		}
	}
	return allDone, false
}

//
func AuthSMTPdPlugins(user, passwd string, success bool, s *core.SMTPServerSession) {
	for _, yag := range s.YagPlugins {
		v, err := yag.Yag.Eval(yag.Name + ".auth")
		if err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s failed to Eval in auth: %s", yag.Name, err))
			continue
		}
		hookFunc, ok := v.Interface().(func(user, passwd string, success bool, s *core.SMTPServerSession) error)
		if !ok {
			s.LogDebug(fmt.Sprintf("plugin %s hook auth is wrong type", yag.Name))
			continue
		}
		err = hookFunc(user, passwd, success, s)
		if err != nil {
			s.LogDebug(fmt.Sprintf("plugin %s returned error in hook auth: %s", yag.Name, err))
			continue
		}
	}
	return
}
