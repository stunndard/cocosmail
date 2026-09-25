# cocosmail

**An email server for human beings.**

cocosmail is a complete, self-hosted mail server in a single binary. It
receives mail for your domains, delivers it to local mailboxes, lets you
read it over POP3, and sends your outgoing mail to the rest of the
internet. There is no Postfix + Dovecot + OpenDKIM + queue daemon + database
server to glue together: one program, one folder, one config file.

> **Status:** usable, work in progress. Configuration currently lives in a
> plain text file (`conf/cocosmail.cfg`). An interactive, Turbo Vision style
> text UI for configuration is planned, see [Roadmap](#roadmap).

## What you get

- **SMTP server**: receives mail from the internet (MX) and from your own mail
  clients (submission). STARTTLS, implicit TLS (SMTPS), `AUTH PLAIN` and
  `AUTH LOGIN`. Authentication is only allowed over an encrypted connection.
  TLS 1.2 or newer only.
- **POP3 server**: POP3 over TLS (POP3S) for reading your mail.
- **Local mailboxes**: built-in Maildir delivery. You can also hand mail over to
  Dovecot's LDA if you want IMAP through Dovecot.
- **Outgoing delivery**: queue with retries and bounces, MX lookup, optional
  static routes (per domain, sender or user), failover/round-robin across
  several local IPs, STARTTLS to remote servers, DKIM signing.
- **Anti-abuse**: SPF checks (adds `Received-SPF`, can reject), optional
  ClamAV scanning, relay control per IP or per authenticated user, a fail2ban
  style plugin.
- **IPv4 and IPv6** for SMTP (in and out) and POP3.
- **Aliases and catch-all**, including piping mail to a command.
- **Plugins** written in plain Go, loaded at runtime without recompiling.
- **Batteries included**: the message queue (nsqd) and the default database
  (SQLite) are embedded. MySQL/MariaDB and PostgreSQL are supported too.
- **CLI** to manage domains, users, aliases, routes, DKIM and the queue, plus a
  small REST API.

## What's in the folder

Everything cocosmail needs lives in one directory (`dist/` in this repo):

| Path          | What it is                                                     |
|---------------|----------------------------------------------------------------|
| `cocosmail`   | the binary (you build it, see below)                            |
| `run`         | helper script: loads the config and starts the server           |
| `conf/`       | `cocosmail.cfg.base` is the documented example config            |
| `ssl/`        | TLS certificates and keys                                      |
| `tpl/`        | text templates (bounce messages)                               |
| `plugins/`    | runtime plugins and `config.go`, which enables them             |
| `db/`         | SQLite database (created on first run)                         |
| `store/`      | messages waiting in the queue                                  |
| `mailboxes/`  | users' Maildirs                                                |

`nsq/` and `bolt/` are created automatically for the internal queue and cache.

## Quick start

These steps set up a server for `example.com` whose hostname is
`mail.example.com`. Replace them with your own names.

### 1. Build

You need a Go toolchain.

```sh
git clone https://github.com/stunndard/cocosmail.git
cd cocosmail
go build -o dist/cocosmail
```

(or `task build` if you use [Task](https://taskfile.dev)).

### 2. Install

Run cocosmail as its own unprivileged user:

```sh
sudo adduser --disabled-password cocosmail
sudo cp -r dist /home/cocosmail/dist
sudo chown -R cocosmail: /home/cocosmail/dist
sudo -iu cocosmail
cd ~/dist
mkdir -p db store mailboxes
```

### 3. Configure

```sh
cp conf/cocosmail.cfg.base conf/cocosmail.cfg
chmod 600 conf/cocosmail.cfg
```

The config file is a shell script made of `export COCOSMAIL_...=...` lines.
Every option is documented inside it. For a first setup you only need to
check these:

| Setting                          | Set it to                                                    |
|----------------------------------|--------------------------------------------------------------|
| `COCOSMAIL_ME`                   | your server's hostname, e.g. `mail.example.com`              |
| `COCOSMAIL_DB_SOURCE`            | path of the SQLite file, e.g. `/home/cocosmail/dist/db/cocosmail.db?_busy_timeout=60000` |
| `COCOSMAIL_STORE_SOURCE`         | `/home/cocosmail/dist/store`                                 |
| `COCOSMAIL_USERS_HOME_BASE`      | `/home/cocosmail/dist/mailboxes`                             |
| `COCOSMAIL_PLUGIN_PATH`          | `/home/cocosmail/dist/plugins`                               |
| `COCOSMAIL_SMTPD_DSNS`           | where SMTP listens (see [Listeners](#listeners))            |
| `COCOSMAIL_POP3D_DSNS`           | where POP3 listens                                           |
| `COCOSMAIL_DELIVERD_LOCAL_IPS`   | local IPs used for outgoing mail; `0.0.0.0&::` is fine for most |

The example config already uses `/home/cocosmail/dist`. If you installed
elsewhere, change those paths.

A typical listener setup for a public server:

```sh
export COCOSMAIL_SMTPD_DSNS="[::]:25:mail.example.com:nossl:example.com;[::]:587:mail.example.com:nossl:example.com;[::]:465:mail.example.com:ssl:example.com"
export COCOSMAIL_POP3D_DSNS="[::]:995:mail.example.com:ssl:example.com"
```

- port 25: mail from other servers (STARTTLS available)
- port 587: your mail clients, with STARTTLS + login
- port 465: your mail clients, with implicit TLS + login
- port 995: POP3 over TLS

### 4. Certificates

For each listener, the last DSN field (`example.com` above) is a certificate
name. cocosmail loads:

- `ssl/smtp-<name>.crt` and `ssl/smtp-<name>.key` for SMTP (used for SMTPS and
  for STARTTLS)
- `ssl/pop3-<name>.crt` and `ssl/pop3-<name>.key` for POP3

With [Let's Encrypt](https://letsencrypt.org/) (certbot), for example:

```sh
sudo certbot certonly --standalone -d mail.example.com
cd /home/cocosmail/dist/ssl
for p in smtp pop3; do
  sudo cp /etc/letsencrypt/live/mail.example.com/fullchain.pem $p-example.com.crt
  sudo cp /etc/letsencrypt/live/mail.example.com/privkey.pem   $p-example.com.key
done
sudo chown cocosmail: *.crt *.key && sudo chmod 600 *.key
```

For a quick test, a self-signed certificate works too:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=mail.example.com \
  -keyout ssl/smtp-example.com.key -out ssl/smtp-example.com.crt
cp ssl/smtp-example.com.key ssl/pop3-example.com.key
cp ssl/smtp-example.com.crt ssl/pop3-example.com.crt
```

cocosmail stops at startup if a POP3 or SMTPS certificate is missing.

### 5. First start

```sh
./run
```

On the first start cocosmail sees an empty database and asks whether to create
the tables. Answer `y`. **Do this first start in a terminal**, not from a
service manager, because it waits for your answer.

```
Database 'driver: sqlite3, source: ...' misses some tables.
Should i create them ? (y/n): y
... smtpd [::]:25 launched.
... pop3d [::]:995 SSL launched
... deliverd launched
```

### 6. Add your domain and a mailbox

In a second terminal, as the `cocosmail` user in `~/dist`:

```sh
. conf/cocosmail.cfg                              # the CLI reads the same config
./cocosmail rcpthost add -l example.com           # accept mail for example.com, deliver locally
./cocosmail user add -m -r you@example.com 'a-good-password'
```

`-m` gives the user a mailbox and `-r` allows them to send mail out through
the server after logging in.

Configure your mail client with:

- incoming: POP3, `mail.example.com`, port 995, SSL/TLS, login `you@example.com`
- outgoing: SMTP, `mail.example.com`, port 587 (STARTTLS) or 465 (SSL/TLS),
  same login

### 7. DNS

Other servers must be able to find and trust you. At your DNS provider:

| Record                          | Value                                                     |
|---------------------------------|-----------------------------------------------------------|
| `mail.example.com` A / AAAA     | your server's IPv4 / IPv6 address                         |
| `example.com` MX                | `10 mail.example.com.`                                    |
| `example.com` TXT (SPF)         | `v=spf1 mx -all`                                          |
| DKIM TXT                        | output of `./cocosmail dkim getdnsrecord example.com`     |
| reverse DNS (PTR)               | set `mail.example.com` for each IP, at your hosting provider |

To sign outgoing mail with DKIM:

```sh
./cocosmail dkim enable example.com
./cocosmail dkim getdnsrecord example.com   # publish this record
```

and set `COCOSMAIL_DELIVERD_DKIM_SIGN=true` in the config.

### Ports below 1024

cocosmail doesn't need root. Allow the binary to bind privileged ports:

```sh
sudo setcap cap_net_bind_service=+ep /home/cocosmail/dist/cocosmail
```

(repeat after every rebuild), or use `AmbientCapabilities` in the systemd unit
below.

### Running as a service (systemd)

`/etc/systemd/system/cocosmail.service`:

```ini
[Unit]
Description=cocosmail mail server
After=network-online.target
Wants=network-online.target

[Service]
User=cocosmail
WorkingDirectory=/home/cocosmail/dist
ExecStart=/bin/sh -c '. conf/cocosmail.cfg && exec ./cocosmail'
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cocosmail
journalctl -u cocosmail -f
```

## Listeners

`COCOSMAIL_SMTPD_DSNS` and `COCOSMAIL_POP3D_DSNS` are lists of listeners
separated by `;`. Each listener is:

```
IP:PORT:HOSTNAME:SSL:CERT
```

| Field      | Meaning                                                            |
|------------|--------------------------------------------------------------------|
| `IP`       | address to listen on (see below)                                   |
| `PORT`     | TCP port                                                           |
| `HOSTNAME` | name used in the greeting and `Received:` headers                  |
| `SSL`      | `ssl`: encrypted from the start (implicit TLS). `nossl`: starts in clear text, STARTTLS available (SMTP only) |
| `CERT`     | certificate name: `ssl/smtp-CERT.*` or `ssl/pop3-CERT.*`           |

The IP can be:

- an IPv4 address: `192.0.2.10:25:...`
- an IPv6 address **in square brackets**: `[2001:db8::10]:25:...`. Link-local
  addresses need their interface: `[fe80::1%eth0]:25:...`
- `[::]`, `0.0.0.0` or empty (`:25:...`): all addresses, IPv4 **and** IPv6.
  This relies on the operating system allowing dual-stack sockets, which is
  the default on Linux.

POP3 has no STARTTLS (STLS), so a POP3 listener must use `ssl`. cocosmail
refuses to start with `nossl` for POP3, except on a loopback address
(`127.0.0.1` or `[::1]`), for example behind a local TLS proxy.

To listen only on specific addresses, list them separately:

```sh
export COCOSMAIL_SMTPD_DSNS="192.0.2.10:25:mail.example.com:nossl:example.com;[2001:db8::10]:25:mail.example.com:nossl:example.com"
```

## Outgoing mail and IPv6

`COCOSMAIL_DELIVERD_LOCAL_IPS` lists the local addresses used to connect to
other servers:

- `&` between addresses means failover: try them in order.
- `|` means round-robin: pick them in random order. Don't mix `&` and `|`.
- Add `:hostname` to use a specific HELO name for an address. IPv6 addresses
  need brackets when followed by a hostname: `[2001:db8::10]:mail.example.com`.
- `0.0.0.0` is any local IPv4 address and `::` is any local IPv6 address.

An IPv4 local address is only used for IPv4 destinations and an IPv6 one only
for IPv6 destinations. The default `0.0.0.0&::` sends over IPv4 when possible
and falls back to IPv6. `0.0.0.0` alone disables outgoing IPv6.

The same syntax is used for the `-l` option of `cocosmail routes add`.

## Command line

Run `./cocosmail help` or `./cocosmail <command> help` for details. The CLI
uses the same config, so load it first (`. conf/cocosmail.cfg`).

| Command     | Subcommands                                               | Purpose                               |
|-------------|-----------------------------------------------------------|---------------------------------------|
| `rcpthost`  | `add`, `list`, `del`                                      | domains cocosmail accepts mail for (`-l` = local mailboxes) |
| `user`      | `add`, `del`, `update`, `list`, `catchall`                | users, mailboxes, SMTP login, quota   |
| `alias`     | `add`, `del`, `list`                                      | aliases, forwarding, pipe to command  |
| `relayip`   | `add`, `list`, `del`                                      | IPs (v4 or v6) allowed to relay without login |
| `routes`    | `add`, `list`, `del`                                      | static routes for outgoing mail       |
| `dkim`      | `enable`, `disable`, `getdnsrecord`, `getpubkey`, `getprivkey` | DKIM keys per domain             |
| `queue`     | `list`, `count`, `discard`, `bounce`, `purge`             | outgoing mail queue                   |

Example: send all mail for `example.net` through a smarthost:

```sh
./cocosmail routes add -d example.net -rh smtp.provider.net -rp 587 -rl login -rpwd password
```

## Plugins

Plugins are Go source files that cocosmail interprets at runtime (with
[yaegi](https://github.com/traefik/yaegi)), so you don't need a Go toolchain
on the server to change them. They live in `plugins/<name>/<name>.go` and hook
into the SMTP session: `connect`, `helo`, `mailpre`, `mailpost`, `rcptto`,
`data`, `beforequeue`, `quit`, `exitasap` and `auth`.

`plugins/config.go` lists which plugins are active, in order. Two examples
ship with cocosmail:

- `fail2ban`: bans IPs after repeated failed logins.
- `customgreeting`: replaces the SMTP greeting. This is a demo, so remove it
  from `config.go` on a real server.

## Other options

`conf/cocosmail.cfg.base` documents everything else, including SPF policy
(`COCOSMAIL_SMTPD_SPF_ACTION`), message size limit, ClamAV, Dovecot LDA,
MySQL/PostgreSQL, the REST API, queue lifetimes and RFC strictness switches.

## Roadmap

- **Text UI configurator**: a Turbo Vision style interface, built on
  [vtui](https://github.com/unxed/vtui), to set cocosmail up without editing
  the config file by hand.

See [TODO.md](TODO.md) for known issues.

## Contributing

Issues and pull requests are welcome. If you run cocosmail, feedback on what
was hard to set up is especially useful: making setup easy is the point of
this project.

## Credits and license

cocosmail started as [tmail](https://github.com/toorop/tmail) by Stéphane
Depierrepont (Toorop) and is developed in this fork.

MIT, see [LICENSE](LICENSE).
