package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"syscall"
	"time"

	"github.com/nsqio/nsq/nsqd"
	"github.com/stunndard/cocosmail/plugin"
	"github.com/stunndard/cocosmail/pop3"
	"github.com/urfave/cli"

	tcli "github.com/stunndard/cocosmail/cli"
	"github.com/stunndard/cocosmail/core"
	"github.com/stunndard/cocosmail/rest"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	var err error
	if err = core.Bootstrap(); err != nil {
		log.Fatalln(err)
	}
	core.Version = core.CocosmailVersion

	if os.RemoveAll(path.Join(core.Cfg.GetBasePath(), "nsq")) != nil {
		log.Fatalln("Unable to delete nsq data directory")
	}
	// Check base path structure
	requiredPaths := []string{"nsq", "ssl", "bolt"}
	for _, p := range requiredPaths {
		if err = os.MkdirAll(path.Join(core.Cfg.GetBasePath(), p), 0700); err != nil {
			log.Fatalln("Unable to create path "+path.Join(core.Cfg.GetBasePath(), p), " - ", err.Error())
		}
	}

	// TODO: if clusterMode check if nsqlookupd is available

	// check DB
	// TODO: do check in CLI call (raise error & ask for user to run cocosmail initdb|checkdb)
	if !core.IsOkDB(core.DB) {
		var r []byte
		for {
			fmt.Printf("Database 'driver: %s, source: %s' misses some tables.\r\nShould i create them ? (y/n):", core.Cfg.GetDbDriver(), core.Cfg.GetDbSource())
			r, _, _ = bufio.NewReader(os.Stdin).ReadLine()
			if r[0] == 110 || r[0] == 121 {
				break
			}
		}
		if r[0] == 121 {
			if err = core.InitDB(core.DB); err != nil {
				log.Fatalln(err)
			}
		} else {
			log.Println("See you soon...")
			os.Exit(0)
		}
	}
	// sync tables from structs
	if err := core.AutoMigrateDB(core.DB); err != nil {
		log.Fatalln(err)
	}

	// init rand seed
	rand.Seed(time.Now().UTC().UnixNano())

	// Dovecot support
	if core.Cfg.GetDovecotSupportEnabled() {
		_, err := exec.LookPath(core.Cfg.GetDovecotLda())
		if err != nil {
			log.Fatalln("Unable to find Dovecot LDA binary, checks your config poarameter COCOSMAIL_DOVECOT_LDA ", err)
		}
	}
}

// MAIN
func main() {
	var err error
	app := cli.NewApp()
	app.Name = "cocosmail"
	app.Usage = "Email system"
	app.Version = core.CocosmailVersion
	app.Commands = tcli.CliCommands
	// no know command ? Launch server
	app.Action = func(c *cli.Context) {
		if len(c.Args()) != 0 {
			_ = cli.ShowAppHelp(c)
		} else {
			// if there is nothing to do then... do nothing
			if !core.Cfg.GetLaunchDeliverd() && !core.Cfg.GetLaunchSmtpd() {
				log.Fatalln("I have nothing to do, so i do nothing. Bye.")
			}

			// Init Bolt (used as cache)
			if err = core.InitBolt(); err != nil {
				log.Fatalln("Init bolt failed", err)
			}

			// Loop
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			// init and launch nsqd
			opts := nsqd.NewOptions()
			opts.Logger = log.New(ioutil.Discard, "", 0)
			//opts.Logger = core.NewNSQLogger()
			//opts.Verbose = core.Cfg.GetDebugEnabled()
			opts.DataPath = core.Cfg.GetBasePath() + "/nsq"
			opts.TCPAddress = "127.0.0.1:4150"
			opts.HTTPAddress = "127.0.0.1:4151"
			// if cluster get lookupd addresses
			if core.Cfg.GetClusterModeEnabled() {
				opts.NSQLookupdTCPAddresses = core.Cfg.GetNSQLookupdTcpAddresses()
			}

			// deflate (compression)
			opts.DeflateEnabled = true

			// if a message timeout it returns to the queue: https://groups.google.com/d/msg/nsq-users/xBQF1q4srUM/kX22TIoIs-QJ
			// msg timeout : base time to wait from consummer before requeuing a message
			// note: deliverd consumer return immediatly (message is handled in a go routine)
			// Ce qui est au dessus est faux malgres la go routine il attends toujours a la réponse
			// et c'est normal car le message est toujours "in flight"
			// En fait ce timeout c'est le temps durant lequel le message peut rester dans le state "in flight"
			// autrement dit c'est le temps maxi que peu prendre deliverd.processMsg
			opts.MsgTimeout = 10 * time.Minute

			// maximum duration before a message will timeout
			opts.MaxMsgTimeout = 15 * time.Hour

			// maximum requeuing timeout for a message
			// si le client ne demande pas de requeue dans ce delais alors
			// le message et considéré comme traité
			opts.MaxReqTimeout = 1 * time.Hour

			// Number of message in RAM before synching to disk
			opts.MemQueueSize = 0

			nsqDaemon := nsqd.New(opts)
			_ = nsqDaemon.LoadMetadata()
			if err = nsqDaemon.PersistMetadata(); err != nil {
				log.Fatalf("ERROR: failed to persist metadata - %s", err.Error())
			}
			nsqDaemon.Main()

			// smtpd
			if core.Cfg.GetLaunchSmtpd() {
				plugin.InitModule()
				// clamav ?
				if core.Cfg.GetSmtpdClamavEnabled() {
					if err = core.NewClamav().Ping(); err != nil {
						log.Fatalln("Unable to connect to clamd -", err)
					}
				}
				smtpdDsns, err := core.GetDsnsFromString(core.Cfg.GetSmtpdDsns())
				if err != nil {
					log.Fatalln("unable to parse smtpd dsn -", err)
				}
				for _, dsn := range smtpdDsns {
					go core.NewSmtpd(dsn).ListenAndServe()
					// TODO at this point we don't know if serveur is launched
					core.Logger.Info("smtpd " + dsn.String() + " launched.")
				}
			}

			// deliverd
			if core.Cfg.GetLaunchDeliverd() {
				core.RequeueAll()
				go core.LaunchDeliverd()
			}

			// HTTP REST server
			if core.Cfg.GetRestServerLaunch() {
				go rest.LaunchServer()
			}

			// POP3 server
			if core.Cfg.GetLaunchPop3() {
				pop3Dsn, err := core.GetDsnsFromString(core.Cfg.GetPop3Dsns())
				if err != nil {
					log.Fatalln("unable to parse pop3 dsn -", err)
				}
				go pop3.NewPop3d(pop3Dsn[0]).ListenAndServe()
			}

			// runtime stats
			if core.Cfg.GetDebugEnabled() {
				go NewMonitor(60)
			}

			<-sigChan
			core.Logger.Info("Exiting...")

			// close NsqQueueProducer if exists
			if core.Cfg.GetLaunchSmtpd() {
				core.NsqQueueProducer.Stop()
			}

			// flush nsqd memory to disk
			nsqDaemon.Exit()

			// exit
			os.Exit(0)
		}
	}
	_ = app.Run(os.Args)

}

type Monitor struct {
	Alloc,
	TotalAlloc,
	Sys,
	Mallocs,
	Frees,
	LiveObjects,
	PauseTotalNs uint64
	NumGC        uint32
	NumGoroutine int
}

func NewMonitor(duration int) {
	var m Monitor
	var rtm runtime.MemStats
	var interval = time.Duration(duration) * time.Second
	for {
		<-time.After(interval)

		// Read full mem stats
		runtime.ReadMemStats(&rtm)

		// Number of goroutines
		m.NumGoroutine = runtime.NumGoroutine()

		// Misc memory stats
		m.Alloc = rtm.Alloc
		m.TotalAlloc = rtm.TotalAlloc
		m.Sys = rtm.Sys
		m.Mallocs = rtm.Mallocs
		m.Frees = rtm.Frees

		// Live objects = Mallocs - Frees
		m.LiveObjects = m.Mallocs - m.Frees

		// GC Stats
		m.PauseTotalNs = rtm.PauseTotalNs
		m.NumGC = rtm.NumGC

		// Just encode to json and print
		b, _ := json.Marshal(m)
		core.Logger.Debug(fmt.Sprintf("runtime stats: %s", string(b)))
	}
}
