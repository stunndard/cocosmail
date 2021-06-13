# cocosmail

cocosmail is a email server (SMTP/POP3/...)

cocosmail is a fast and compact all-in-one solution for a personal self hosted email. The modern trends show that people move their email from big bad corporations to their personal servers. And this is where cocosmail steps in to help. Aimed to be very simple and extremely easy to setup and deploy for anyone (WIP).

## Features

 * SMTP, SMTP over SSL, ESMTP (SIZE, AUTH PLAIN, STARTTLS), POP3, POP3S
 * Advanced routing for outgoing mails (failover and round robin on routes, route by recipient, sender, authuser... )
 * SMTPAUTH (plain & cram-md5) for in/outgoing mails
 * STARTTLS/SSL for in/outgoing connections.
 * Manageable via CLI or REST API.
 * DKIM support for signing outgoing mails.
 * Builtin support of clamav (open-source antivirus scanner).
 * Builtin Dovecot (imap server) support.
 * Builtin deliverd supporting maildir.
 * Fully extendable via plugins
 * Easy to deploy
 * No dependencies, single binary: -> you do not have to install nor maintain libs
 * Scriptable with easy procedural scripts at every email receiving/forwarding/alias/antispam step, no more cryptic configs for complicated actions (todo)


### add user cocosmail

	adduser cocosmail

### Fetch cocosmail dist

	# su cocosmail
	$ cd
	$ wget ftp://ftp.cocosmail./softs/cocosmail/cocosmail.zip
	$ unzip cocosmail.zip
	$ cd dist

Under dist you will find:

* conf: configuration.
* run: script used to launch cocosmail
* ssl: is the place to store SSL cert. For testing purpose you can use those included.
* cocosmail: cocosmail binary
* tpl: text templates.
* db: if you use sqlite as DB backend (MySQL and Postgresql are also supported), sqlite file will be stored in this directory.
* store: mainly used to store raw email when they are in queue. (others kind of backend/storage engine are coming)
* mailboxes: where mailboxes are stored if you activate Dovecot support.

Make run script and cocosmail runnable:

	chmod 700 run cocosmail

add directories:

	mkdir db
	mkdir store


if you want to enable Dovecot support add mailboxes directory:

	mkdir mailboxes

See [Enabling Dovecot support for cocosmail (french)](http://cocosmail.io/doc/mailboxes/) for more info.


### Configuration

Init you conf file:

	cd conf
	cp cocosmail.cfg.base cocosmail.cfg
	chmod 600 cocosmail.cfg

* COCOSMAIL_ME: Hostname of the SMTP server (will be used for HELO|EHLO)

* COCOSMAIL_DB_DRIVER: I recommend sqlite3 unless you want to enable clustering (or you have a lot of domains/mailboxes)

* COCOSMAIL_SMTPD_DSNS: listening IP(s), port(s) and SSL options (see conf file for more info)

* COCOSMAIL_DELIVERD_LOCAL_IPS: IP(s) to use for sending mail to remote host.

* COCOSMAIL_SMTPD_CONCURRENCY_INCOMING: max concurent incomming proccess

* COCOSMAIL_DELIVERD_MAX_IN_FLIGHT: concurrent delivery proccess


### Init database

	cocosmail@dev:~/dist$ ./run
	Database 'driver: sqlite3, source: /home/cocosmail/dist/db/cocosmail.db' misses some tables.
	Should i create them ? (y/n): y

	[dev.cocosmail.io - 127.0.0.1] 2015/02/02 12:42:32.449597 INFO - smtpd 151.80.115.83:2525 launched.
	[dev.cocosmail.io - 127.0.0.1] 2015/02/02 12:42:32.449931 INFO - smtpd 151.80.115.83:5877 launched.
	[dev.cocosmail.io - 127.0.0.1] 2015/02/02 12:42:32.450011 INFO - smtpd 151.80.115.83:4655 SSL launched.
	[dev.cocosmail.io - 127.0.0.1] 2015/02/02 12:42:32.499728 INFO - deliverd launched

### Port forwarding

As you run cocosmail under cocosmail user, it can't open port under 1024 (and for now cocosmail can be launched as root, open port under 25 and fork itself to unprivilegied user).

The workaround is to use iptables to forward ports.
For example, if we have cocosmail listening on ports 2525, and 5877 and we want tu use 25 and 587 as public ports, we have to use those iptables rules:

	iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525
	iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-port 5877

### First test

	$ telnet dev.cocosmail.io 25
	Trying 151.80.115.83...
	Connected to dev.cocosmail.io.
	Escape character is '^]'.
	220 cocosmail.io  cocosmail ESMTP f22815e0988b8766b6fe69cbc73fb0d965754f60
	HELO toto
	250 cocosmail.io
	MAIL FROM: cocos@cocosmail.io
	250 ok
	RCPT TO: cocos@cocosmail.io
	554 5.7.1 <cocos@cocosmail.io>: Relay access denied.
	Connection closed by foreign host.

Perfect !
You got "Relay access denied" because by default noboby can use cocosmail for relaying mails.

### Relaying mails for @example.com

If you want cocosmail to relay mails for example.com, just run:

	cocosmail rcpthost add example.com

Note: If you have activated Dovecot support and example.com is a local domain, add -l flag :

	cocosmail rcpthost add -l example.com

Does it work as expected ?

	$ telnet dev.cocosmail.io 25
	Trying 151.80.115.83...
	Connected to dev.cocosmail.io.
	Escape character is '^]'.
	220 cocosmail.io  cocosmail ESMTP 96b78ef8f850253cc956820a874e8ce40773bfb7
	HELO toto
	250 cocosmail.io
	mail from: cocos@cocosmail.io
	250 ok
	rcpt to: cocos@example.com
	250 ok
	data
	354 End data with <CR><LF>.<CR><LF>
	subject: test cocosmail

	blabla
	.
	250 2.0.0 Ok: queued 2736698d73c044fd7f1994e76814d737c702a25e
	quit
	221 2.0.0 Bye
	Connection closed by foreign host.

Yes ;)

### Allow relay from an IP

	cocosmail relayip add IP

For example:

	cocosmail relayip add 127.0.0.1


### Basic routing

By default cocosmail will use MX records for routing mails, but you can "manualy" configure alternative routing.
If you want cocosmail to route mail from @example.com to mx.slowmail.com. It is as easy as adding this routing rule

	cocosmail routes add -d example.com -rh mx.slowmail.com

You can find more elaborated routing rules on [cocosmail routing documentation (french)](http://cocosmail.io/doc/cli-gestion-route-smtp/) (translators are welcomed ;))

### SMTP AUTH

If you want to enable relaying after SMTP AUTH for user cocos@cocosmail.io, just enter:

	cocosmail user add -r cocos@cocosmail.io password


If you want to delete user cocos@cocosmail.io :

	cocosmail user del cocos@cocosmail.io


### Let's Encrypt (TLS/SSL)

If you want to activate TLS/SSL connections with a valid certificate (not an auto-signed one as it's by default) between mail clients and your cocosmail server you can get a let's Encrypt certificate, you have first to install let's Encrypt :

	cd ~
	git clone https://github.com/letsencrypt/letsencrypt
	cd letsencrypt

Then you can request a certificate

	./letsencrypt-auto certonly --standalone -d your.hostname

You'll have to provide a valid mail address and agree to the Let's Encrypt Term of Service. When certificate is issued you have to copy some files to the ssl/ directory

	cd /home/cocosmail/dist/ssl
	cp /etc/letsencrypt/live/your.hostname/fullchain.pem server.crt
	cp /etc/letsencrypt/live/your.hostname/privkey.pem server.key
	chown cocosmail.cocosmail server.*

And it's done !


## Contribute

Feel free to inspect & improve cocosmail code, PR are welcomed ;)

If you are not a coder, you can contribute too:

* install and use cocosmail, I need feebacks.

* as you can see reading this page, english is not my native language, so I need help to write english documentation.


## Roadmap

 * clustering
 * IPV6
 * write unit tests (yes i know...)
 * improve, refactor, optimize
 * test test test test


## License
MIT, see LICENSE


## Imported packages

github.com/nsqio/nsq/...
github.com/urfave/cli
github.com/codegangsta/negroni
github.com/go-sql-driver/mysql
github.com/jinzhu/gorm
github.com/julienschmidt/httprouter
github.com/kless/osutil/user/crypt/...
github.com/lib/pq
github.com/mattn/go-sqlite3
github.com/nbio/httpcontext
golang.org/x/crypto/bcrypt
golang.org/x/crypto/blowfish
