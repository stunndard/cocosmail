package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/stunndard/cocosmail/core"
	cgCli "github.com/urfave/cli"
	"golang.org/x/term"
)

// Init writes the missing default files next to the binary and creates the
// database tables. Unlike the other commands it works on an empty database.
// Without settings, it sets up a server with defaults for its hostname.
var Init = cgCli.Command{
	Name: "init",
	Usage: "Write missing default files (conf, plugins, ssl, tpl) and create database tables. " +
		"Without settings yet, asks for the server hostname and sets up SMTP, IMAP, POP3 and delivery. " +
		"Safe to run again, existing files, settings and data are kept.",
	Flags: []cgCli.Flag{cgCli.StringFlag{
		Name:  "hostname",
		Usage: "hostname of the server, like mail.example.com, instead of asking",
	}},
	// the files first, then the DB: see Action
	Before: func(c *cgCli.Context) error { return nil },
	Action: func(c *cgCli.Context) {
		written, err := core.WriteDefaultFiles(core.BaseDir())
		cliHandleErr(err)
		for _, f := range written {
			fmt.Println("created " + f)
		}
		cliHandleErr(core.Bootstrap())
		cliHandleErr(InitDB())
		fmt.Printf("Database '%s' is ready.\n", core.Cfg.GetDbDriver())
		initSettings(c.String("hostname"))
		cliDieOk()
	},
}

// initSettings sets up a server with defaults for hostname, asked if it's
// empty, when the database has no settings and conf/cocosmail.yaml doesn't
// give them
func initSettings(hostname string) {
	if core.ConfigFilePath != "" || core.SettingsManagedBy(core.DB) != "" {
		return
	}
	path, err := core.ImportDefaultConfig(core.DB)
	cliHandleErr(err)
	if path != "" {
		fmt.Println("imported " + path)
		return
	}
	stored, err := core.SettingsFromDB(core.DB)
	cliHandleErr(err)
	if len(stored) > 0 {
		if hostname != "" {
			fmt.Println("settings exist already, --hostname not used: change them with cocosmail config edit")
		}
		return
	}
	if hostname == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Println("No settings yet: cocosmail init --hostname mail.example.com, or cocosmail config edit")
			return
		}
		fmt.Print("Hostname of this server, like mail.example.com (empty: configure it later): ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if hostname = strings.TrimSpace(line); hostname == "" {
			fmt.Println("Configure it with: cocosmail config edit")
			return
		}
	}
	done, err := core.Setup(core.DB, hostname)
	for _, d := range done {
		fmt.Println("created " + d)
	}
	cliHandleErr(err)
	fmt.Println("Next: add users with cocosmail config edit, then create the DNS records of cocosmail config export-dns")
}

// InitDB creates missing tables and syncs existing ones with the structs
func InitDB() error {
	if err := core.InitDB(core.DB); err != nil {
		return err
	}
	return core.AutoMigrateDB(core.DB)
}
