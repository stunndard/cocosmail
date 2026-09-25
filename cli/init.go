package cli

import (
	"fmt"

	"github.com/stunndard/cocosmail/core"
	cgCli "github.com/urfave/cli"
)

// Init creates the database tables. Unlike the other commands it works on an
// empty database, so it only needs config, logger and DB.
var Init = cgCli.Command{
	Name:  "init",
	Usage: "Create database tables. Safe to run again, existing data is kept.",
	Before: func(c *cgCli.Context) error {
		return core.Bootstrap()
	},
	Action: func(c *cgCli.Context) {
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
