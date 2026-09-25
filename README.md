# cocosmail

**An email server for human beings.**

cocosmail is a complete, self-hosted mail server in a single binary. It
receives mail for your domains, delivers it to local mailboxes, lets you
read it over POP3, and sends your outgoing mail to the rest of the
internet. There is no Postfix + Dovecot + OpenDKIM + queue daemon + database
server to glue together: one program, one folder, one config file.

> **Status:** usable, work in progress. Settings and data (domains, users,
> aliases, relay IPs, routes, DKIM keys) are kept in the database and managed
> with a text UI, `cocosmail config edit`. One YAML file holds all of it, to
> set up, back up or move a server.

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

Everything cocosmail needs lives in one directory, next to the binary
(`dist/` in this repo). The default files are also embedded in the binary, and
`cocosmail init` writes the missing ones. Copy or zip the directory and it
works on another server as is:

| Path          | What it is                                                     |
|---------------|----------------------------------------------------------------|
| `cocosmail`   | the binary (you build it, see below)                            |
| `run`         | helper script: starts the server from its own directory         |
| `conf/`       | `cocosmail.yaml.base` is the documented example config           |
| `ssl/`        | TLS certificates and keys                                      |
| `tpl/`        | text templates (bounce messages)                               |
| `plugins/`    | runtime plugins and `config.go`, which enables them             |
| `db/`         | SQLite database (created on first run)                         |
| `store/`      | messages waiting in the queue                                  |
| `mailboxes/`  | users' Maildirs                                                |
| `log/`        | log file, when `logpath` is a file name (default: stdout) |

`nsq/` and `bolt/` are created automatically for the internal queue and cache.

## Quick start

These steps set up a server for `example.com` whose hostname is
`mail.example.com`. Replace them with your own names.

### 1. Build

You need Go 1.26.6 or newer (an older `go` command downloads it
automatically) and a C compiler, because SQLite is built with cgo.

```sh
git clone https://github.com/stunndard/cocosmail.git
cd cocosmail
go build -tags goffi_static -o dist/cocosmail
```

(or `task build` if you use [Task](https://taskfile.dev)). The `goffi_static`
tag is needed: the text UI library pulls in an FFI layer (for graphical
backends cocosmail doesn't use) that doesn't link in cgo builds otherwise.
Without it, the build stops with `undefined:
build_with_go_build_tags_goffi_static`. Tests: `go test -tags goffi_static ./...`

To build a fully static binary that runs on any Linux, including old
distributions and minimal containers (needs static glibc, `libc6-dev` on
Debian/Ubuntu):

```sh
CGO_ENABLED=1 go build -trimpath \
  -tags 'netgo osusergo sqlite_omit_load_extension goffi_static' \
  -ldflags '-s -w -linkmode external -extldflags "-static"' \
  -o dist/cocosmail
```

(or `task build-static`).

### 2. Install

Run cocosmail as its own unprivileged user. Only the binary is needed:
`cocosmail init` writes the default files (config example, plugins, bounce
template, ssl/README.txt) next to it, and creates the database:

```sh
sudo adduser --disabled-password cocosmail
sudo mkdir /home/cocosmail/dist
sudo cp dist/cocosmail /home/cocosmail/dist/
sudo chown -R cocosmail: /home/cocosmail/dist
sudo -iu cocosmail
cd ~/dist
./cocosmail init
```

`init` never changes existing files: run it again after an upgrade to get
files added by the new version, or to restore a deleted one.

### 3. Configure

The easiest way is the text UI: `./cocosmail config edit` (see
[Text UI](#text-ui)). It works in a fresh directory: like `cocosmail init`, it
creates the database and the missing default files, and it imports
`conf/cocosmail.yaml` if there is one. Starting cocosmail without the
required settings also offers to open it. Or write a config file:

```sh
cp conf/cocosmail.yaml.base conf/cocosmail.yaml
chmod 600 conf/cocosmail.yaml
```

The config file is YAML: the settings under `settings:`, one `key: value`
per line, each documented inside it. It can also hold domains, users and the
other data, see [Settings and data](#settings-and-data). At the first start
it's imported into the database. For a first setup you only need to check
these settings:

| Setting              | Set it to                                                    |
|----------------------|--------------------------------------------------------------|
| `me`                 | your server's hostname, e.g. `mail.example.com`              |
| `smtpd_dsns`         | where SMTP listens (see [Listeners](#listeners))            |
| `pop3d_dsns`         | where POP3 listens                                           |
| `deliverd_local_ips` | local IPs used for outgoing mail; `0.0.0.0&::` is fine for most |

In the environment, a setting is `COCOSMAIL_` and its name in capitals, e.g.
`COCOSMAIL_ME`: it overrides the file.

Paths in the config (database, store, mailboxes, plugins) are relative to
the directory of the `cocosmail` binary, and missing directories are created.
You can install it anywhere, and later move or copy the whole directory to
another server as is.

A typical listener setup for a public server:

```yaml
  smtpd_dsns: '[::]:25:mail.example.com:nossl:example.com;[::]:587:mail.example.com:nossl:example.com;[::]:465:mail.example.com:ssl:example.com'
  pop3d_dsns: '[::]:995:mail.example.com:ssl:example.com'
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

Create the database tables, then start the server:

```sh
./cocosmail init
./run
```

```
Database 'sqlite3' is ready.
... settings imported from /home/cocosmail/dist/conf/cocosmail.yaml, from now on the database is the source of truth
... smtpd [::]:25 launched.
... pop3d [::]:995 SSL launched
... deliverd launched
```

`cocosmail init` is safe to run again, existing data is kept. If you skip it
and start the server in a terminal, cocosmail offers to create the tables. From
a service manager or Docker it stops and tells you to run `cocosmail init`.
The same goes for missing settings: in a terminal cocosmail offers to open the
configurator and starts once they're set, otherwise it says what's missing.

### 6. Add your domain and a mailbox

In a second terminal, as the `cocosmail` user in `~/dist`, run
`./cocosmail config edit`, select **Users** in the section list and press F7:
enter `you@example.com` and a password, keep **Mailbox** (gets mail) and
**Relay** (can send mail out after logging in) checked. The domain
`example.com` is added with it. F2 saves.

Or on the command line:

```sh
./cocosmail rcpthost add -l example.com           # accept mail for example.com, deliver locally
./cocosmail user add -m -r you@example.com 'a-good-password'
```

Or before the first start, in `conf/cocosmail.yaml`:

```yaml
domains:
  - name: example.com
    local: true
users:
  - login: you@example.com
    password: a-good-password   # hashed when imported
    mailbox: true
    relay: true
```

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
| DKIM TXT                        | shown by the text UI (DKIM keys, F6), or `./cocosmail dkim getdnsrecord example.com` |
| reverse DNS (PTR)               | set `mail.example.com` for each IP, at your hosting provider |

To sign outgoing mail with DKIM, add a key in the text UI (**DKIM keys**, F7,
the domain) and publish the record F6 shows. Or:

```sh
./cocosmail dkim enable example.com
./cocosmail dkim getdnsrecord example.com   # publish this record
```

and enable signing: `./cocosmail config set deliverd_dkim_sign true`.

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
ExecStart=/home/cocosmail/dist/cocosmail
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

`smtpd_dsns` and `pop3d_dsns` are lists of listeners
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

```yaml
  smtpd_dsns: '192.0.2.10:25:mail.example.com:nossl:example.com;[2001:db8::10]:25:mail.example.com:nossl:example.com'
```

## Outgoing mail and IPv6

`deliverd_local_ips` lists the local addresses used to connect to
other servers:

- `&` between addresses means failover: try them in order.
- `|` means round-robin: pick them in random order. Don't mix `&` and `|`.
- Add `:hostname` to use a specific HELO name for an address. IPv6 addresses
  need brackets when followed by a hostname: `[2001:db8::10]:mail.example.com`.
- `0.0.0.0` is any local IPv4 address and `::` is any local IPv6 address.

An IPv4 local address is only used for IPv4 destinations and an IPv6 one only
for IPv6 destinations. The default `0.0.0.0&::` sends over IPv4 when possible
and falls back to IPv6. `0.0.0.0` alone disables outgoing IPv6.

The same syntax is used for the local IPs of a route.

## Command line

Run `./cocosmail help` or `./cocosmail <command> help` for details.

| Command     | Subcommands                                               | Purpose                               |
|-------------|-----------------------------------------------------------|---------------------------------------|
| `init`      |                                                           | write missing default files, create database tables (safe to repeat) |
| `config`    | `edit`, `list`, `get`, `set`, `unset`, `import`, `export`, `convert` | settings and data, in the database or in a config file (`--file`) |
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
- `customgreeting`: replaces the SMTP greeting. It's an example, not enabled
  by default.

## Other options

`conf/cocosmail.yaml.base` documents everything else, including SPF policy
(`smtpd_spf_action`), message size limit, ClamAV, Dovecot LDA,
MySQL/PostgreSQL, the REST API, queue lifetimes and RFC strictness switches.

## Settings and data

cocosmail keeps two things in its database:

- **settings**: the ~60 options documented in `conf/cocosmail.yaml.base`;
- **data**: domains, users, aliases, relay IPs, routes and DKIM keys.

Only `db_driver` and `db_source` stay outside, because
they say where the database is. By default it's SQLite in `db/` next to the
binary, so there's nothing to set.

One YAML file holds both: `settings:`, then the data sections `domains:`,
`users:`, `aliases:`, `relay_ips:`, `routes:` and `dkim:`:

```sh
./cocosmail config export all.yaml             # settings and data, to back up or move
./cocosmail config import all.yaml             # on any server
./cocosmail config import --dry-run all.yaml   # only show what would change
```

- **Settings:** `import` gives settings that are not in the file their default.
  `--merge` changes only the settings in the file.
- **Data:** items in the file are added or changed. Everything else in the
  database is kept, unless `--replace`: then it's deleted.
- **Passwords:**
  - `export` writes password hashes, which `import` reads back as they are.
  - A user can also be given `password: ...` in clear text, which is hashed
    when imported.
  - `export --no-secrets` leaves password hashes, route passwords, DKIM
    private keys and secret settings empty. Importing it keeps the ones
    already in the database.
- **Checks:** everything is checked before anything is written. For example,
  the domain of a mailbox or an address alias must exist and be local. An
  alias can deliver to any addresses: mailboxes, other aliases, or addresses
  elsewhere (forwarding).

There are two ways to run cocosmail:

**Database mode** (`./cocosmail`, `./run`): the database is the source of
truth. At the first start, `conf/cocosmail.yaml` is imported into it,
settings and data. Then:

```sh
./cocosmail config edit                        # text UI, see below
./cocosmail config list                        # values, and where they come from
./cocosmail config set smtpd_max_hops 30       # applied within a few seconds
./cocosmail config unset smtpd_max_hops        # back to the default
```

A running cocosmail checks for changed settings every few seconds (at once on
`SIGHUP`). Most settings are applied immediately. Settings like listeners,
database or log path need a restart: cocosmail first checks that it will
start with them (certificates, free ports, POP3 encryption...), then restarts
itself in the same process, so systemd or docker don't notice. It stops
accepting SMTP connections, waits up to 30 seconds for open sessions and
deliveries, then restarts. If the check fails, cocosmail keeps running with the
previous settings, writes them back to the database and logs why. Data changes
(a new user, a new domain) are used at once. Editing `conf/cocosmail.yaml`
after the first start changes nothing until you import it, except
`db_driver` and `db_source`: they're always read from it (or from the
environment), since they can't be in the database.

**File mode** (`./cocosmail --config FILE`, or `COCOSMAIL_CONFIG=FILE`): that's
the mode for docker. The settings of the file are loaded into the database at
every start, and `COCOSMAIL_*` environment variables override them.
`config set` is refused, and `import` skips the settings: change the file
and restart instead, e.g. with `./cocosmail config set --file cocosmail.yaml
KEY VALUE`. The data of the file is imported only into an empty database, at
the first start. Then users and domains live in the database (the docker
volume) and are managed while it runs, with
`docker exec -it CONTAINER ./cocosmail config edit`. A restart doesn't undo
these changes. Starting once without `--config` switches back to database
mode, keeping everything.

### Text UI

`./cocosmail config edit` shows the sections on the left and the settings of
the selected section on the right, with the description of the selected
setting below. It works on the database, or on a config file with
`--file FILE` (no database needed, e.g. to prepare a server offline).

| Key            | Action                                                   |
|----------------|----------------------------------------------------------|
| F1             | help                                                     |
| Tab            | switch between the section list and the settings         |
| Enter, F4      | edit the setting, `true`/`false` ones are switched       |
| typing         | search a setting by name in the section, Esc clears it   |
| F8             | reset the setting to its default                         |
| F3             | show or hide secrets, also in dialogs: secret settings, route passwords (user passwords are stored as hashes, they can't be shown) |
| F2             | save, after showing what changed                         |
| F10, Esc       | quit, asks to save unsaved changes                       |

The entry "all settings" shows every settings section at once. Below it are
the data sections: Domains, Users, Aliases, Relay IPs, Routes and DKIM keys,
one item per row.
- **Keys:** F7 or Ins adds an item, F4 or Enter edits it, F8 or Del deletes
  it, and in DKIM keys, F6 shows the DNS record to publish.
- **Saving:** like settings, changes are saved with F2.
- **Checks:** each change is checked with the rest. A domain that still has
  users can't be deleted. A mailbox or an alias in a new domain adds the
  domain.
- **With settings managed by a file (file mode):** the data can still be
  edited here, only the settings are read only.

Lists have their own editor, one row per item, opened with Enter: the
listeners (`smtpd_dsns`, `pop3d_dsns`: IP, port, hostname, SSL, certificate)
and the local IPs for outgoing mail (`deliverd_local_ips`: IP, HELO hostname,
F3 switches failover and round robin). There, F7 or Ins adds, F4 or Enter
edits, F5 copies, F8 or Del deletes, Ctrl+Up/Down moves, F2 applies and F10
closes; the key bar at the bottom shows them.

Values are checked before they're accepted. Settings that tell where the
database is, and settings managed by a file in file mode, are read only.

`config get`, `set`, `unset` and `list` also work on a file with
`--file FILE`, without a database. Files are written in YAML, keeping your
comments. Older versions used one `COCOSMAIL_KEY=value` per line (or
`export COCOSMAIL_KEY="value"`); such files are still read by `import` and
`--config`, but not written. Convert them with:

```sh
./cocosmail config convert old.cfg conf/cocosmail.yaml
```

It fixes what it can (e.g. `true`/`false` listeners become `ssl`/`nossl`) and
warns about settings with wrong names, which older versions silently ignored.
Without `conf/cocosmail.yaml`, an old `conf/cocosmail.cfg` is still used.

## Roadmap

See [TODO.md](TODO.md) for plans and known issues.

## Contributing

Issues and pull requests are welcome. If you run cocosmail, feedback on what
was hard to set up is especially useful: making setup easy is the point of
this project.

## Credits and license

cocosmail started as [tmail](https://github.com/toorop/tmail) by Stéphane
Depierrepont (Toorop) and is developed in this fork.

MIT, see [LICENSE](LICENSE).
