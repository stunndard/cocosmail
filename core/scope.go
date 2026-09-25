package core

// TODO: nsq logger

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nsqio/go-nsq"
	"github.com/sirupsen/logrus"
)

const (
	// CocosmailVersion version of cocosmail
	CocosmailVersion = "0.2.0"
)

const (
	// Time822 format time for RFC 822
	Time822 = "Mon, 02 Jan 2006 15:04:05 -0700" // "Mon, 02 Jan 06 15:04 -0700"
)

var (
	// Version is tamil version
	Version string
	Cfg     *Config
	DB      *gorm.DB
	Bolt    *bolt.DB
	//Log                              *Logger
	Logger                           *logrus.Logger
	NsqQueueProducer                 *nsq.Producer
	SmtpSessionsCount                int32
	DeliverdConcurrencyLocalCount    int32
	DeliverdConcurrencyRemoteCount   int32
	Store                            Storer
)

// Bootstrap loads config and opens logger, DB and store.
// It's all the CLI needs; the server needs more, see InitMailQueueProducer.
// TODO check validity of each element
func Bootstrap() (err error) {
	// until config is loaded
	Logger = logrus.New()

	// Load config from environment, it tells where the DB is
	Cfg, err = InitConfig("cocosmail")
	if err != nil {
		return
	}

	if err = openDB(Cfg.GetDbDriver(), Cfg.GetDbSource()); err != nil {
		return
	}

	// settings stored in DB override environment
	stored, err := SettingsFromDB(DB)
	if err != nil {
		return err
	}
	if len(stored) > 0 {
		values := SettingsFromEnv("cocosmail")
		for k, v := range stored {
			values[k] = v
		}
		if err = Cfg.Load(values); err != nil {
			return errors.New("settings in database: " + err.Error())
		}
	}
	if err = initLogger(); err != nil {
		return err
	}
	DB.SetLogger(Logger)
	DB.LogMode(Cfg.GetDebugEnabled())

	if os.Getenv("COCOSMAIL_BASE_PATH") != "" {
		Logger.Warn("COCOSMAIL_BASE_PATH is not used anymore, relative paths are relative to " + BaseDir())
	}

	/*
		// openstack
		if Cfg.GetOpenstackEnable() {
			if !context.Keyring.IsPopulate() {
				return errors.New("No credentials found from ENV. See http://docs.openstack.org/cli-reference/content/cli_openrc.html")
			}
			// Do auth
			err = identity.DoAuth()
			if err != nil {
				return err
			}
			// auto update Token
			identity.AutoUpdate(30, new(log.Logger))
		}
	*/

	// init store
	if Cfg.GetStoreDriver() == "disk" {
		if err = os.MkdirAll(diskStorePath(Cfg.GetStoreSource()), 0700); err != nil {
			return
		}
	}
	Store, err = NewStore(Cfg.GetStoreDriver(), Cfg.GetStoreSource())
	if err != nil {
		return err
	}
	// TODO gestion erreur
	//execCocosMailPlugins("postinit")

	return
}

// OpenDB opens the database from COCOSMAIL_DB_DRIVER and COCOSMAIL_DB_SOURCE only.
// Other settings are not loaded: config commands must work even when they're
// missing or invalid, to fix them.
func OpenDB() error {
	Logger = logrus.New()
	driver := os.Getenv(SettingEnvName("db_driver"))
	if driver == "" {
		driver = "sqlite3"
	}
	if err := ValidateSetting("db_driver", driver); err != nil {
		return err
	}
	return openDB(driver, dbSource(driver, os.Getenv(SettingEnvName("db_source"))))
}

// openDB opens and pings DB
func openDB(driver, source string) (err error) {
	if driver != "sqlite3" && (source == "" || source == defaultSqliteSource) {
		return errors.New("COCOSMAIL_DB_SOURCE is needed for database driver " + driver)
	}
	// sqlite doesn't create missing directories
	if driver == "sqlite3" {
		dbFile := strings.SplitN(source, "?", 2)[0]
		if !strings.HasPrefix(dbFile, "file:") && !strings.HasPrefix(dbFile, ":memory:") {
			if err = os.MkdirAll(filepath.Dir(dbFile), 0700); err != nil {
				return
			}
		}
	}
	DB, err = gorm.Open(driver, source)
	if err != nil {
		return
	}
	if DB.DB().Ping() != nil {
		return errors.New("I could not access to database " + driver + " " + source)
	}
	return nil
}

// initLogger sets Logger from config
func initLogger() (err error) {
	var out io.Writer

	logPath := Cfg.GetLogPath()
	logger := logrus.New()
	//customFormatter := new(logrus.TextFormatter)
	//customFormatter := new(FileFormatter)
	if logPath == "stdout" {
		out = os.Stdout
		f := new(logrus.TextFormatter)
		f.TimestampFormat = time.RFC3339Nano
		f.FullTimestamp = true
		logger.Formatter = f

	} else if logPath == "discard" {
		out = ioutil.Discard
		f := new(logrus.TextFormatter)
		f.TimestampFormat = time.RFC3339Nano
		f.FullTimestamp = true
		logger.Formatter = f
	} else {
		file := path.Join(logPath, "current.log")
		out, err = os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		f := new(FileFormatter)
		f.TimestampFormat = time.RFC3339Nano
		f.FullTimestamp = true
		logger.Formatter = f
	}

	if Cfg.GetDebugEnabled() {
		logger.Level = logrus.DebugLevel
	} else {
		logger.Level = logrus.InfoLevel
	}
	logger.Out = out
	Logger = logger
	Logger.Debug("Logger initialized")
	return nil
}

// InitBolt init bolt
func InitBolt() error {
	var err error
	// init Bolt DB
	Bolt, err = bolt.Open(GetBoltFilePath(), 0600, nil)
	if err != nil {
		return err
	}
	// create buckets if not exists
	return Bolt.Update(func(tx *bolt.Tx) error {
		if _, err = tx.CreateBucketIfNotExists([]byte("koip")); err != nil {
			return err
		}
		return nil
	})
}

// InitMailQueueProducer init producer for queue, used by smtpd
func InitMailQueueProducer() (err error) {
	nsqCfg := nsq.NewConfig()
	nsqCfg.UserAgent = "cocosmail.queue"
	NsqQueueProducer, err = nsq.NewProducer("127.0.0.1:4150", nsqCfg)
	if Cfg.GetDebugEnabled() {
		NsqQueueProducer.SetLogger(NewNSQLogger(), nsq.LogLevelDebug)
	} else {
		NsqQueueProducer.SetLogger(NewNSQLogger(), nsq.LogLevelError)
	}
	return err
}
