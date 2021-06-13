package cli

/*
import (
	"fmt"
	"github.com/stunndard/cocosmail/api"
	cgCli "github.com/urfave/cli"
)

var Mailbox = cgCli.Command{
	Name:  "mailbox",
	Usage: "commands to manage mailboxes",
	Subcommands: []cgCli.Command{
		// Add a mailbox
		{
			Name:        "add",
			Usage:       "Add a mailbox",
			Description: "cocosmail mailbox add MAILBOX",
			Action: func(c *cgCli.Context) {
				if len(c.Args()) == 0 {
					cliDieBadArgs(c)
				}
				err := api.MailboxAdd(c.Args().First())
				cliHandleErr(err)
			},
		},
		// List Mailboxes
		{
			Name:        "list",
			Usage:       "List mailboxes",
			Description: "cocosmail mailbox list [-d domain]",
			Action: func(c *cgCli.Context) {
				mailboxes, err := api.MailboxList()
				cliHandleErr(err)
				if len(mailboxes) == 0 {
					println("There no mailboxes yet.")
				} else {
					for _, mailbox := range mailboxes {
						line := fmt.Sprintf("%d %s@%s", mailbox.Id, mailbox.LocalPart, mailbox.DomainPart)
						fmt.Println(line)
					}
				}
			},
		},
		// Delete a mailbox
		{
			Name:        "del",
			Usage:       "Delete a mailbox",
			Description: "cocosmail mailbox delete MAILBOX",
			Action: func(c *cgCli.Context) {
				if len(c.Args()) == 0 {
					cliDieBadArgs(c)
				}
				err := api.MailboxDel(c.Args().First())
				cliHandleErr(err)
			},
		},
	},
}*/
