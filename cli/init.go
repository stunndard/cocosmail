package cli

import (
	"fmt"

	"github.com/stunndard/cocosmail/core"
	cgCli "github.com/urfave/cli"
)

// Init writes the missing default files next to the binary and creates the
// database tables. Unlike the other commands it works on an empty database.
var Init = cgCli.Command{
	Name:  "init",
	Usage: "Write missing default files (conf, plugins, ssl, tpl) and create database tables. Safe to run again, existing files and data are kept.",
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
		cliDieOk()
	},
}

// InitDB creates missing tables and syncs existing ones with the structs
func InitDB() error {
	if err := core.InitDB(core.DB); err != nil {
		return err
	}
	return core.AutoMigrateDB(core.DB)
}
