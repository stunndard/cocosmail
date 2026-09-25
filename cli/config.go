package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/cocosmail/tui"
	cgCli "github.com/urfave/cli"
)

var fileFlag = cgCli.StringFlag{
	Name:  "file, f",
	Usage: "work on this config file instead of the database",
}

// Config manages settings, in the database or in a config file
var Config = cgCli.Command{
	Name:  "config",
	Usage: "commands to manage settings, in the database or in a config file (--file)",
	// only needs the DB, and not with --file: see configDB
	Before: func(c *cgCli.Context) error { return nil },
	Subcommands: []cgCli.Command{
		{
			Name:        "list",
			Usage:       "List settings with their value and where it comes from",
			Description: "cocosmail config list [--file FILE] [--secrets]",
			Flags: []cgCli.Flag{fileFlag, cgCli.BoolFlag{
				Name:  "secrets",
				Usage: "show secret values",
			}},
			Action: func(c *cgCli.Context) {
				values, sources := configValues(c)
				width := 0
				for _, s := range core.Settings {
					if l := len(core.SettingEnvName(s.Key)); l > width {
						width = l
					}
				}
				section := ""
				for _, s := range core.Settings {
					if s.Section != section {
						section = s.Section
						fmt.Printf("\n[%s]\n", section)
					}
					v := values[s.Key]
					// a default is never secret
					if s.Secret && v != "" && v != s.Default && !c.Bool("secrets") {
						v = "********"
					}
					fmt.Printf("  %-*s  %-7s  %s\n", width, core.SettingEnvName(s.Key), sources[s.Key], v)
				}
				cliDieOk()
			},
		},
		{
			Name:  "edit",
			Usage: "Edit settings in a text UI, in the database or in a config file (--file)",
			Description: "cocosmail config edit [--file FILE]\n" +
				"   F4 or Enter edits a setting, F8 resets it to its default, F2 saves, F10 quits.",
			Flags: []cgCli.Flag{fileFlag},
			Action: func(c *cgCli.Context) {
				var store tui.Store
				if path := c.String("file"); path != "" {
					store = &tui.FileStore{Path: path}
				} else {
					configDB()
					store = &tui.DBStore{}
				}
				cliHandleErr(tui.Run(store))
				cliDieOk()
			},
		},
		{
			Name:        "get",
			Usage:       "Print the value of a setting",
			Description: "cocosmail config get KEY [--file FILE]",
			Flags:       []cgCli.Flag{fileFlag},
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 1 {
					cliDieBadArgs(c, "KEY is missing")
				}
				key := settingKey(c.Args().First())
				values, _ := configValues(c)
				fmt.Println(values[key])
				cliDieOk()
			},
		},
		{
			Name:        "set",
			Usage:       "Set a setting",
			Description: "cocosmail config set KEY VALUE [--file FILE]\n   KEY is like smtpd_dsns or COCOSMAIL_SMTPD_DSNS",
			Flags:       []cgCli.Flag{fileFlag},
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 2 {
					cliDieBadArgs(c, "KEY and VALUE are needed")
				}
				configSet(c, settingKey(c.Args()[0]), c.Args()[1])
			},
		},
		{
			Name:        "unset",
			Usage:       "Reset a setting to its default",
			Description: "cocosmail config unset KEY [--file FILE]",
			Flags:       []cgCli.Flag{fileFlag},
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 1 {
					cliDieBadArgs(c, "KEY is missing")
				}
				key := settingKey(c.Args().First())
				s, _ := core.SettingByKey(key)
				configSet(c, key, s.Default)
			},
		},
		{
			Name:  "import",
			Usage: "Import settings from a config file into the database",
			Description: "cocosmail config import FILE [--merge]\n" +
				"   Settings not in FILE get their default, unless --merge: then they're kept.\n" +
				"   Old style files (export COCOSMAIL_KEY=\"value\") are accepted.",
			Flags: []cgCli.Flag{cgCli.BoolFlag{
				Name:  "merge",
				Usage: "only change settings that are in FILE",
			}},
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 1 {
					cliDieBadArgs(c, "FILE is missing")
				}
				values := readConfigFile(c.Args().First())
				for _, s := range core.Settings {
					if v, ok := values[s.Key]; ok && s.Bootstrap {
						delete(values, s.Key)
						if v != "" && v != s.Default {
							fmt.Printf("note: %s is not imported, it tells where the database is: keep it in environment\n", core.SettingEnvName(s.Key))
						}
					}
				}
				configDB()
				dieIfManaged()
				changed, err := core.ImportSettings(core.DB, values, c.Bool("merge"))
				cliHandleErr(err)
				fmt.Printf("%d settings imported, %d changed.\n", len(values), len(changed))
				applyNotice(changed)
				cliDieOk()
			},
		},
		{
			Name:  "export",
			Usage: "Export settings to a config file, or to stdout",
			Description: "cocosmail config export [FILE] [--no-secrets]\n" +
				"   If FILE exists, its values are updated and its comments kept.",
			Flags: []cgCli.Flag{cgCli.BoolFlag{
				Name:  "no-secrets",
				Usage: "leave secret values empty",
			}},
			Action: func(c *cgCli.Context) {
				configDB()
				values, _, err := core.EffectiveSettings(core.DB)
				cliHandleErr(err)
				if c.Bool("no-secrets") {
					for _, s := range core.Settings {
						if s.Secret {
							values[s.Key] = ""
						}
					}
				}
				if len(c.Args()) == 0 {
					os.Stdout.Write(core.NewConfigFile(values).Bytes())
					cliDieOk()
				}
				path := c.Args().First()
				f := core.NewConfigFile(values)
				if _, err := os.Stat(path); err == nil {
					f, _, err = core.ReadConfigFile(path)
					cliHandleErr(err)
					for _, s := range core.Settings {
						f.Set(s.Key, values[s.Key])
					}
				}
				cliHandleErr(f.Write(path))
				fmt.Printf("Settings exported to %s\n", path)
				cliDieOk()
			},
		},
		{
			Name:  "convert",
			Usage: "Convert an old style config file to the current format",
			Description: "cocosmail config convert OLDFILE NEWFILE\n" +
				"   Writes all settings with their description, old values are fixed when possible.",
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 2 {
					cliDieBadArgs(c, "OLDFILE and NEWFILE are needed")
				}
				values := readConfigFile(c.Args()[0])
				if _, err := os.Stat(c.Args()[1]); err == nil {
					cliHandleErr(errors.New(c.Args()[1] + " exists"))
				}
				cliHandleErr(core.NewConfigFile(values).Write(c.Args()[1]))
				fmt.Printf("%s written.\n", c.Args()[1])
				if errs := core.ValidateSettings(values); len(errs) > 0 {
					fmt.Println("Fix these settings in it:")
					for _, e := range errs {
						fmt.Println("  " + e.Error())
					}
					os.Exit(1)
				}
				cliDieOk()
			},
		},
	},
}

// settingKey normalizes key, dies if it's unknown
func settingKey(key string) string {
	k := core.NormalizeSettingKey(key)
	if _, ok := core.SettingByKey(k); !ok {
		cliHandleErr(errors.New("unknown setting " + key))
	}
	return k
}

// configDB opens the database, only it: other settings may be invalid, to be fixed
func configDB() {
	cliHandleErr(core.OpenDB())
}

// configValues returns settings values and sources, from --file or from database
func configValues(c *cgCli.Context) (values, sources map[string]string) {
	if path := c.String("file"); path != "" {
		values = core.SettingsDefaults()
		sources = make(map[string]string, len(values))
		for k := range values {
			sources[k] = core.SourceDefault
		}
		for k, v := range readConfigFile(path) {
			values[k], sources[k] = v, core.SourceFile
		}
		return
	}
	configDB()
	values, sources, err := core.EffectiveSettings(core.DB)
	cliHandleErr(err)
	return
}

// configSet sets key in --file or in database
func configSet(c *cgCli.Context, key, value string) {
	cliHandleErr(core.ValidateSetting(key, value))
	s, _ := core.SettingByKey(key)

	if path := c.String("file"); path != "" {
		f := core.NewConfigFile(nil)
		if _, err := os.Stat(path); err == nil {
			f, _, err = core.ReadConfigFile(path)
			cliHandleErr(err)
		}
		f.Set(key, value)
		cliHandleErr(f.Write(path))
		fmt.Printf("%s=%s\n", core.SettingEnvName(key), value)
		cliDieOk()
	}

	if s.Bootstrap {
		cliHandleErr(errors.New(core.SettingEnvName(key) + " tells where the database is, set it in environment"))
	}
	configDB()
	dieIfManaged()
	stored, err := core.SettingsFromDB(core.DB)
	cliHandleErr(err)
	if len(stored) == 0 {
		cliHandleErr(errors.New("settings are not in the database yet, they come from environment and defaults.\n" +
			"Import your config file first: cocosmail config import conf/cocosmail.cfg"))
	}
	cliHandleErr(core.SettingsToDB(core.DB, map[string]string{key: value}))
	fmt.Printf("%s=%s\n", core.SettingEnvName(key), value)
	applyNotice([]string{key})
	cliDieOk()
}

// applyNotice tells how changed settings get applied by a running server
func applyNotice(changed []string) {
	if len(changed) == 0 {
		return
	}
	for _, key := range changed {
		if s, _ := core.SettingByKey(key); s.Restart {
			fmt.Println("A running cocosmail restarts itself within a few seconds to apply it.")
			return
		}
	}
	fmt.Println("A running cocosmail applies it within a few seconds.")
}

// readConfigFile reads settings from path, prints warnings, dies on error
func readConfigFile(path string) map[string]string {
	values, warnings, err := core.ReadSettingsFile(path)
	cliHandleErr(err)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning: "+path+": "+w)
	}
	return values
}

// dieIfManaged dies if settings in DB are managed by a config file (file mode):
// they'd be replaced by the file at next start
func dieIfManaged() {
	if path := core.SettingsManagedBy(core.DB); path != "" {
		cliHandleErr(errors.New("settings are managed by " + path + ", the server loads it at every start.\n" +
			"Change it instead: cocosmail config set --file " + path + " KEY VALUE, then restart cocosmail"))
	}
}
