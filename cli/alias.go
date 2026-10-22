package cli

import (
	"strings"

	"github.com/stunndard/cocosmail/api"
	cgCli "github.com/urfave/cli"
)

var alias = cgCli.Command{
	Name:  "alias",
	Usage: "commands to manage aliases",
	Subcommands: []cgCli.Command{
		// users
		{
			Name:  "add",
			Usage: "Add an alias",
			Description: "cocosmail alias add [--pipe COMMAND] [--deliver-to ADDRESSES] [--minilist] ALIAS\n" +
				"   ALIAS is an address (sales@example.com), its domain is added as local if needed,\n" +
				"   or a domain (example.org) delivering to the same addresses of --deliver-to DOMAIN.",
			Flags: []cgCli.Flag{
				cgCli.StringFlag{
					Name:  "pipe, p",
					Usage: "mail is piped to this command, it must exist on this server",
				},
				cgCli.StringFlag{
					Name:  "deliver-to, d",
					Usage: "addresses separated by spaces, here or elsewhere; for a domain alias, a local domain",
				},
				cgCli.BoolFlag{
					Name:  "minilist, m",
					Usage: "the alias becomes the sender (envelope MAIL FROM), bounces come back to it",
				},
			},
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 1 {
					cliDieBadArgs(c)
				}
				err := api.AliasAdd(c.Args()[0], c.String("d"), c.String("p"), c.Bool("m"))
				cliHandleErr(err)
				cliDieOk()
			},
		}, {
			Name:        "del",
			Usage:       "Delete an alias",
			Description: "cocosmail alias del ALIAS",
			Action: func(c *cgCli.Context) {
				if len(c.Args()) != 1 {
					cliDieBadArgs(c)
				}
				err := api.AliasDel(c.Args()[0])
				cliHandleErr(err)
				cliDieOk()
			},
		}, {
			Name:        "list",
			Usage:       "list all aliases",
			Description: "cocosmail alias list",
			Action: func(c *cgCli.Context) {
				aliases, err := api.AliasList()
				cliHandleErr(err)
				if len(aliases) == 0 {
					println("there is no alias defined")
				} else {
					for _, alias := range aliases {
						println(alias.Alias)
						if alias.Pipe != "" {
							println("\tPipe: " + alias.Pipe)
						}
						for _, d := range strings.Split(alias.DeliverTo, ";") {
							if d != "" {
								println("\t-> " + d)
							}
						}
						println(" ")
					}
				}
				cliDieOk()
			},
		},
	},
}
