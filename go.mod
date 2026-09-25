module github.com/stunndard/cocosmail

go 1.26.6

require (
	blitiri.com.ar/go/spf v1.5.1
	github.com/boltdb/bolt v1.3.1
	github.com/codegangsta/negroni v1.0.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/jinzhu/gorm v1.9.16
	github.com/julienschmidt/httprouter v1.3.0
	github.com/lib/pq v1.10.2
	github.com/mattn/go-sqlite3 v1.14.7
	github.com/nbio/httpcontext v0.0.0-20150224063329-d2f7bb023e6e
	github.com/nsqio/go-nsq v1.0.8
	github.com/nsqio/nsq v1.1.0-rc1.0.20180802175327-996be6d66d20
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/stunndard/go-maildir v0.3.1-0.20210605034352-5b7dd4cd98f4
	github.com/toorop/go-dkim v0.0.0-20201103131630-e1cd1a0a5208
	github.com/traefik/yaegi v0.9.18
	github.com/tredoe/osutil v1.5.0
	github.com/urfave/cli v1.22.5
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/term v0.46.0
)

require (
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/bmizerany/perks v0.0.0-20141205001514-d9a9656a3a4b // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-test/deep v1.0.7 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/nbio/st v0.0.0-20140626010706-e9e8d9816f32 // indirect
	github.com/nsqio/go-diskqueue v0.0.0-20170827021554-4e924ca77cb3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// vtui (TUI configurator) replaces these with its own forks, and a dependency's
// replace directives are ignored, so they have to be repeated here.
replace github.com/ebitengine/purego => github.com/unxed/pureffi v0.1.20

replace github.com/go-webgpu/goffi => github.com/unxed/goffi v0.1.9
