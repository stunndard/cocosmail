package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

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
	Usage: "commands to manage settings and data, in the database or in a config file (--file)",
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
			Usage: "Edit settings and data (domains, users...) in a text UI, in the database or in a config file (--file)",
			Description: "cocosmail config edit [--file FILE]\n" +
				"   F4 or Enter edits a setting, F8 resets it to its default, F2 saves, F10 quits.\n" +
				"   In data sections, F7 adds an item, F4 edits it, F8 deletes it.",
			Flags: []cgCli.Flag{fileFlag},
			Action: func(c *cgCli.Context) {
				var store tui.Store
				if path := c.String("file"); path != "" {
					store = &tui.FileStore{Path: path}
				} else {
					configDBReady()
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
			Usage: "Import settings and data from a config file into the database",
			Description: "cocosmail config import FILE [--merge] [--replace] [--dry-run]\n" +
				"   Settings not in FILE get their default, unless --merge: then they're kept.\n" +
				"   Data (domains, users, aliases, relay IPs, routes, DKIM keys) is added or\n" +
				"   changed, the rest is kept, unless --replace: then it's deleted.\n" +
				"   Old style files (COCOSMAIL_KEY=value) are accepted.",
			Flags: []cgCli.Flag{
				cgCli.BoolFlag{Name: "merge", Usage: "only change settings that are in FILE"},
				cgCli.BoolFlag{Name: "replace", Usage: "delete data that is not in FILE"},
				cgCli.BoolFlag{Name: "dry-run, n", Usage: "show the changes, don't import"},
			},
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 1 {
					cliDieBadArgs(c, "FILE is missing")
				}
				path := c.Args().First()
				f, values := readConfig(path)
				data, err := f.Data()
				cliHandleErr(err)
				for _, s := range core.Settings {
					if v, ok := values[s.Key]; ok && s.Bootstrap {
						delete(values, s.Key)
						if v != "" && v != s.Default {
							fmt.Printf("note: %s is not imported, it tells where the database is: keep it in environment\n", core.SettingEnvName(s.Key))
						}
					}
				}
				configTables()
				withSettings := len(values) > 0
				if managedBy := core.SettingsManagedBy(core.DB); withSettings && managedBy != "" {
					fmt.Printf("note: settings are not imported, they're managed by %s\n", managedBy)
					withSettings = false
				}
				withData := f.HasData()
				if !withData && c.Bool("replace") {
					fmt.Println("note: data is not changed, " + path + " has no data sections")
				}
				if !withSettings && !withData {
					cliHandleErr(errors.New("nothing to import"))
				}

				// everything is checked before anything is imported
				var changed, dataChanges []string
				if withSettings {
					changed, err = core.CheckImportSettings(core.DB, values, c.Bool("merge"))
					cliHandleErr(err)
				}
				if withData {
					dataChanges, err = core.ImportData(core.DB, data, c.Bool("replace"), true)
					cliHandleErr(err)
				}
				if c.Bool("dry-run") {
					for _, k := range changed {
						fmt.Println("set " + core.SettingEnvName(k))
					}
					for _, ch := range dataChanges {
						fmt.Println(ch)
					}
					fmt.Printf("%d settings and %d data changes, not imported (--dry-run).\n", len(changed), len(dataChanges))
					cliDieOk()
				}
				if withSettings {
					changed, err = core.ImportSettings(core.DB, values, c.Bool("merge"))
					cliHandleErr(err)
					fmt.Printf("%d settings imported, %d changed.\n", len(values), len(changed))
				}
				if withData {
					dataChanges, err = core.ImportData(core.DB, data, c.Bool("replace"), false)
					cliHandleErr(err)
					for _, ch := range dataChanges {
						fmt.Println(ch)
					}
					fmt.Printf("%d data changes.\n", len(dataChanges))
				}
				applyNotice(changed)
				cliDieOk()
			},
		},
		{
			Name:  "export",
			Usage: "Export settings and data to a config file, or to stdout",
			Description: "cocosmail config export [FILE] [--no-secrets]\n" +
				"   One file with all settings and data (domains, users, aliases, relay IPs,\n" +
				"   routes, DKIM keys), to import on any server. DKIM keys come with the DNS\n" +
				"   record to publish, also with --no-secrets.\n" +
				"   If FILE exists, its values are updated and its comments kept.",
			Flags: []cgCli.Flag{cgCli.BoolFlag{
				Name:  "no-secrets",
				Usage: "leave secret values, password hashes and private keys empty",
			}},
			Action: func(c *cgCli.Context) {
				configTables()
				values, _, err := core.EffectiveSettings(core.DB)
				cliHandleErr(err)
				data, err := core.ExportData(core.DB)
				cliHandleErr(err)
				// before the private keys are removed
				data.SetDkimRecords()
				if c.Bool("no-secrets") {
					for _, s := range core.Settings {
						if s.Secret {
							values[s.Key] = ""
						}
					}
					data.RemoveSecrets()
				}
				if len(c.Args()) == 0 {
					os.Stdout.Write(core.NewConfigFile(values, data).Bytes())
					cliDieOk()
				}
				path := c.Args().First()
				f := core.NewConfigFile(values, data)
				if _, err := os.Stat(path); err == nil {
					f, _, err = core.ReadConfigFile(path)
					cliHandleErr(err)
					for _, s := range core.Settings {
						f.Set(s.Key, values[s.Key])
					}
					f.SetData(data)
				}
				cliHandleErr(f.Write(path))
				fmt.Printf("Settings and data exported to %s\n", path)
				cliDieOk()
			},
		},
		{
			Name:  "export-dns",
			Usage: "Export the DNS records the server needs, to a text file or to stdout",
			Description: "cocosmail config export-dns [FILE] [--public-ip IP]... [--check]\n" +
				"   cocosmail config export-dns --zone [DIR]\n" +
				"   MX, A, AAAA, PTR, SPF, DKIM, DMARC and SRV records, by zone, to create in\n" +
				"   DNS panels. From the SMTP, IMAP and POP3 listeners, deliverd local IPs and\n" +
				"   routes, domains, users and DKIM keys. Listeners and local IPs on all\n" +
				"   addresses (0.0.0.0, ::) get the address this server reaches the internet\n" +
				"   with, or --public-ip behind NAT.\n" +
				"   --check looks each record up in DNS, exits with 1 if one isn't right.\n" +
				"   --zone writes zone files to import into DNS providers: DIR/ZONE.zone each,\n" +
				"   and the PTR records in DIR/reverse-dns.txt.",
			Flags: []cgCli.Flag{
				cgCli.StringSliceFlag{
					Name:  "public-ip",
					Usage: "public address of this server, IPv4 and/or IPv6 (repeat the flag)",
				},
				cgCli.BoolFlag{Name: "check", Usage: "look up the records in DNS: ok, missing or different"},
				cgCli.BoolFlag{Name: "zone", Usage: "zone files (RFC 1035) to import, one per zone in DIR"},
			},
			Action: func(c *cgCli.Context) {
				if c.Bool("check") && c.Bool("zone") {
					cliDieBadArgs(c, "--check and --zone don't go together")
				}
				public := map[bool]net.IP{}
				for _, s := range c.StringSlice("public-ip") {
					ip := net.ParseIP(s)
					if ip == nil {
						cliHandleErr(errors.New("--public-ip: invalid address " + s))
					}
					public[ip.To4() == nil] = ip
				}
				hostIP := func(v6 bool) net.IP {
					if ip, ok := public[v6]; ok {
						return ip
					}
					if len(public) > 0 {
						// the other family was given: the server has only it
						return nil
					}
					return core.DNSHostIP(v6)
				}
				configTables()
				values, _, err := core.EffectiveSettings(core.DB)
				cliHandleErr(err)
				data, err := core.ExportData(core.DB)
				cliHandleErr(err)
				data.SetDkimRecords()
				dns := core.ExportDNS(values, data, hostIP)

				if c.Bool("zone") {
					names, files := dns.ZoneFiles()
					reverse := dns.ReverseText()
					if len(c.Args()) == 0 {
						for _, z := range names {
							os.Stdout.WriteString(files[z] + "\n")
						}
						os.Stdout.WriteString(reverse)
						cliDieOk()
					}
					dir := c.Args().First()
					cliHandleErr(os.MkdirAll(dir, 0755))
					for _, z := range names {
						path := filepath.Join(dir, z+".zone")
						cliHandleErr(os.WriteFile(path, []byte(files[z]), 0644))
						fmt.Println(path)
					}
					if reverse != "" {
						path := filepath.Join(dir, "reverse-dns.txt")
						cliHandleErr(os.WriteFile(path, []byte(reverse), 0644))
						fmt.Println(path)
					}
					cliDieOk()
				}

				problems := 0
				if c.Bool("check") {
					problems = dns.Check(net.DefaultResolver)
				}
				text := dns.Text()
				if len(c.Args()) == 0 {
					os.Stdout.WriteString(text)
				} else {
					cliHandleErr(os.WriteFile(c.Args().First(), []byte(text), 0644))
					fmt.Printf("DNS records exported to %s\n", c.Args().First())
					if c.Bool("check") {
						fmt.Printf("%d of %d records not right\n", problems, len(dns.Records))
					}
				}
				if problems > 0 {
					os.Exit(1)
				}
				cliDieOk()
			},
		},
		{
			Name:  "convert",
			Usage: "Convert an old style config file to the current format",
			Description: "cocosmail config convert OLDFILE NEWFILE\n" +
				"   Writes all settings with their description, and the data of OLDFILE.\n" +
				"   Old values are fixed when possible.",
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 2 {
					cliDieBadArgs(c, "OLDFILE and NEWFILE are needed")
				}
				f, values := readConfig(c.Args()[0])
				data, err := f.Data()
				cliHandleErr(err)
				if _, err := os.Stat(c.Args()[1]); err == nil {
					cliHandleErr(errors.New(c.Args()[1] + " exists"))
				}
				cliHandleErr(core.NewConfigFile(values, data).Write(c.Args()[1]))
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

// configTables opens the database and creates missing default files and
// tables, like cocosmail init: data needs the tables
func configTables() {
	configDB()
	fresh := !core.IsOkDB(core.DB)
	if fresh {
		written, err := core.WriteDefaultFiles(core.BaseDir())
		cliHandleErr(err)
		for _, f := range written {
			fmt.Println("created " + f)
		}
	}
	// also tables added since the database was created, e.g. plugins
	cliHandleErr(core.InitDB(core.DB))
	if fresh {
		fmt.Println("database created")
	}
}

// configDBReady is configTables, then conf/cocosmail.yaml is imported if
// there are no settings yet, like at the first start. If the file can't be
// imported, it tells why and goes on: the settings can be fixed in the
// configurator.
func configDBReady() {
	configTables()
	// in file mode, the server loads the file at every start
	if core.ConfigFilePath != "" || core.SettingsManagedBy(core.DB) != "" {
		return
	}
	if path, err := core.ImportDefaultConfig(core.DB); err != nil {
		fmt.Fprintln(os.Stderr, "warning: not imported: "+err.Error())
	} else if path != "" {
		fmt.Println("imported " + path)
	}
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
		f := core.NewConfigFile(nil, nil)
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
	configDBReady()
	dieIfManaged()
	stored, err := core.SettingsFromDB(core.DB)
	cliHandleErr(err)
	if len(stored) == 0 {
		cliHandleErr(errors.New("settings are not in the database yet, they come from environment and defaults.\n" +
			"Import your config file first: cocosmail config import conf/cocosmail.yaml"))
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
	_, values := readConfig(path)
	return values
}

// readConfig reads config file path and its settings, prints warnings, dies on error
func readConfig(path string) (*core.ConfigFile, map[string]string) {
	f, values, warnings, err := core.ReadConfig(path)
	cliHandleErr(err)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning: "+path+": "+w)
	}
	return f, values
}

// dieIfManaged dies if settings in DB are managed by a config file (file mode):
// they'd be replaced by the file at next start
func dieIfManaged() {
	if path := core.SettingsManagedBy(core.DB); path != "" {
		cliHandleErr(errors.New("settings are managed by " + path + ", the server loads it at every start.\n" +
			"Change it instead: cocosmail config set --file " + path + " KEY VALUE, then restart cocosmail"))
	}
}
