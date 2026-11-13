# cocosmail

**An email server for human beings.**

![cocosmail configurator: editing a user](doc/tui.png)

cocosmail is a complete, self-hosted mail server in a single binary. It
receives mail for your domains, delivers it to local mailboxes, lets you read
it over IMAP or POP3 and sends your mail to the rest of the internet. There is no
Postfix + Dovecot + OpenDKIM + queue daemon + database server to glue
together: one program, one folder, and a text UI to set it up.

## Why it's easy

- **One binary, one folder.** The database (SQLite), the queue (nsqd), the
  default files: everything is built in. Everything lives next to the binary.
- **Easy to configure.** `cocosmail config edit` opens a text UI for all
  settings and data: domains, users, aliases, relay IPs, routes and DKIM keys.
  Every setting is described, values are checked before they're accepted, and
  nothing is saved until you press F2 and see what changed. No hand-written
  config files, no `postmap`, no reloads.
- **Changes apply by themselves.** A running server picks up new settings
  within seconds. When a setting needs a restart (listeners, database...),
  cocosmail first checks that it will start with it (certificates, free ports),
  then restarts itself in the same process. If the check fails, it keeps
  running with the old settings and logs why.
- **Easy to back up and move.** Copy the folder to another server and start it.
  Or put everything in one YAML file: `config export` on the old server,
  `config import` on the new one.
- **Easy Docker.** One container, one volume, the config file as the source of
  truth. Users can be added while it runs with `docker exec`.
- **Friendly when something's missing.** Started for the first time in a
  terminal, cocosmail offers to create the database and open the configurator.
  Adding a mailbox in a new domain adds the domain. Errors say what to do.

## What you get

- **SMTP**: receives mail from other servers (MX) and from your mail clients:
  STARTTLS, implicit TLS (SMTPS), `AUTH PLAIN`/`LOGIN`, login only over
  TLS 1.2+.
- **IMAP** with folders (Sent, Drafts, Trash, Junk and Archive are created and
  recognized by mail programs), IDLE (new mail shows up at once), MOVE,
  STARTTLS or TLS. **POP3** over TLS. Both work on the same Maildir at the
  same time, and see each other's changes. Mail can also be delivered by
  Dovecot's LDA.
- **Outgoing mail**: queue with retries and bounces, MX lookup, static routes
  and smarthosts, several local IPs with failover or round robin, STARTTLS,
  **DKIM** signing.
- **Anti-abuse**: SPF checks, DKIM verification of incoming mail (an
  Authentication-Results header, optional rejection rules, domains that must
  sign their mail), optional ClamAV, relay control per IP or per user, a
  fail2ban-style plugin.
- **IPv4 and IPv6** everywhere.
- **Aliases**, forwarding, catch-all, mini mailing lists, piping mail to a
  command.
- **Plugins** in plain Go, loaded at runtime without recompiling.
- SQLite by default, MySQL/MariaDB and PostgreSQL supported. A CLI for
  everything, and a small REST API.

## Quick start

From an empty server to sending and receiving mail, for `mail.example.com`
and the domain `example.com` (use your own names). You need a server with a
public IP where port 25 is open both ways (many cloud providers block it until
you ask), and a domain whose DNS you can edit.

**1. Build and install.** You need Go 1.26.6+ and a C compiler:

```sh
git clone https://github.com/stunndard/cocosmail.git && cd cocosmail
go build -tags goffi_static -o dist/cocosmail      # or: task build
sudo adduser --disabled-password cocosmail
sudo install -d -o cocosmail /home/cocosmail/mail
sudo install -o cocosmail dist/cocosmail /home/cocosmail/mail/
sudo -iu cocosmail
cd ~/mail
```

**2. Set it up.**

```sh
./cocosmail init                  # asks for the hostname: mail.example.com
```

`init` creates the database and a working setup: SMTP on ports 25, 587 and
465, IMAP on 993, POP3 on 995, outgoing mail delivery with DKIM signing, the
domain `example.com` with its DKIM key, and a self-signed certificate.

**3. Add users** in the [text UI](#text-ui-keys): `./cocosmail config edit`.
Add `you@example.com` to **Users**, and `postmaster@example.com` to
**Aliases**, delivered to you. Every other setting is there too, described,
with F1 for help.

**4. Create the DNS records.**

```sh
./cocosmail config export-dns     # MX, A, SPF, DKIM, DMARC, SRV and PTR records
```

Create them in the DNS panel of your domain, or import the zone files of
`export-dns --zone dns/`. Ask your hosting provider to set the reverse DNS
(PTR) of the address. Then check them: `./cocosmail config export-dns --check`.
See [DNS records](#dns-records).

**5. Get a certificate**, once `mail.example.com` resolves to the server:

```sh
sudo certbot certonly --standalone -d mail.example.com
cd /home/cocosmail/mail/ssl
for p in smtp imap pop3; do
  sudo cp /etc/letsencrypt/live/mail.example.com/fullchain.pem $p-mail.example.com.crt
  sudo cp /etc/letsencrypt/live/mail.example.com/privkey.pem   $p-mail.example.com.key
done
sudo chown cocosmail: *-mail.example.com.*
```

They're loaded when they change, no restart needed: put these lines in a
certbot deploy hook for renewals. See [Certificates](#certificates).

**6. Start** it, with systemd to bind ports below 1024 without root:

```ini
# /etc/systemd/system/cocosmail.service
[Unit]
Description=cocosmail mail server
After=network-online.target
Wants=network-online.target

[Service]
User=cocosmail
WorkingDirectory=/home/cocosmail/mail
ExecStart=/home/cocosmail/mail/cocosmail
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now cocosmail && journalctl -u cocosmail -f
```

Mail clients log in as `you@example.com` to `mail.example.com`: IMAP 993 or
POP3 995 with SSL/TLS, SMTP 587 with STARTTLS or 465 with SSL/TLS. Send a
message to Gmail and open "Show original": SPF, DKIM and DMARC should say PASS.

## DNS records

`config export-dns` writes every record the setup needs, from the listeners,
the outgoing IPs, the domains and the DKIM keys, grouped by zone:

```
example.com
  MX    @                    10 mail.example.com
  A     mail                 203.0.113.5
  TXT   @                    v=spf1 ip4:203.0.113.5 -all
  TXT   mail                 v=spf1 a -all
  TXT   20261113._domainkey  v=DKIM1;k=rsa;s=email;h=sha256;p=MIIBIjANBgkq...
  TXT   _dmarc               v=DMARC1; p=none; rua=mailto:postmaster@example.com
  SRV   _submission._tcp     0 1 587 mail.example.com
  ...
Reverse DNS (PTR): set by the provider of each address, not in a zone.
  203.0.113.5  mail.example.com
```

- `@` is the domain itself, `mail` is `mail.example.com`. In most panels, the
  MX priority (`10`) and the SRV priority, weight and port have their own
  fields. TXT values go in whole, without quotes.
- `--zone DIR` writes zone files (`DIR/example.com.zone`, `reverse-dns.txt`)
  for panels that import them (Cloudflare, PowerDNS, BIND...).
- The address is the one the server reaches the internet with. Behind NAT, or
  to choose it: `--public-ip 203.0.113.5` (repeat it for IPv6).
- Each domain gets its own records: the MX of `tenant2.example` is
  `mx.tenant2.example` if a listener has that hostname.
- `--check` looks them up: each is **ok**, **MISSING**, **DIFFERENT** (with
  what was found) or **ERROR**; **optional** ones (SRV) can be left out. A
  different record doing the same job is ok: an SPF of `v=spf1 mx -all`
  allowing the same addresses, any DMARC policy, a DKIM record with the same
  key. It exits with 1 until all are ok. New records can take a few minutes
  to show, changed ones up to their old TTL.

Once SPF, DKIM and DMARC pass for a while, make DMARC stricter: `p=quarantine`,
then `p=reject`. For a new domain, add its users and a DKIM key, then export
and check again.

## Certificates

Each listener names a certificate: `init` uses the hostname. cocosmail loads
`ssl/smtp-NAME.crt`/`.key` for SMTP, `ssl/imap-...` for IMAP and
`ssl/pop3-...` for POP3, and loads them again when the files change. `init`
writes a self-signed one, enough for other servers (they don't check it) but
not for mail clients. Replace it with Let's Encrypt as in the quick start; if
cocosmail can read `/etc/letsencrypt` (root only by default), symlinks to
`live/` work too. Without systemd, `sudo setcap cap_net_bind_service=+ep
cocosmail` (again after each rebuild) lets it bind ports below 1024.

## Docker

A fully static binary runs in any image and on any Linux (needs `libc6-dev`
on Debian/Ubuntu to build):

```sh
CGO_ENABLED=1 go build -trimpath \
  -tags 'netgo osusergo sqlite_omit_load_extension goffi_static' \
  -ldflags '-s -w -linkmode external -extldflags "-static"' \
  -o dist/cocosmail                                # or: task build-static
```

A `Dockerfile`:

```dockerfile
FROM debian:stable-slim
COPY dist/cocosmail /usr/local/bin/cocosmail
WORKDIR /cocosmail
VOLUME /cocosmail
EXPOSE 25 465 587 993 995
# the binary works in its own directory: copied into the volume at each start
CMD cp /usr/local/bin/cocosmail . && ./cocosmail init && \
    exec ./cocosmail --config conf/cocosmail.yaml
```

Put `conf/cocosmail.yaml` and the certificates (`ssl/`) in a directory, then:

```sh
docker build -t cocosmail .
docker run -d --name mail -v /srv/cocosmail:/cocosmail \
  -p 25:25 -p 465:465 -p 587:587 -p 993:993 -p 995:995 cocosmail
docker exec -it mail ./cocosmail config edit      # add users while it runs
```

With `--config`, the settings of the file are loaded at every start, and
`COCOSMAIL_*` environment variables (e.g. `-e COCOSMAIL_ME=mail.example.com`)
override them. Domains and users of the file are imported into an empty
database once; after that they live in the volume and are managed with
`config edit`, and a restart keeps them.

## Back up, move, upgrade

- **The folder is the server.** Stop cocosmail, copy or zip its folder, start
  it anywhere. Paths are relative to the binary.
- **One file for everything:**

  ```sh
  ./cocosmail config export all.yaml             # settings, domains, users, aliases, routes, DKIM keys
  ./cocosmail config import --dry-run all.yaml   # on the new server: show what would change
  ./cocosmail config import all.yaml
  ```

  Password hashes are exported as they are; `export --no-secrets` leaves out
  passwords, keys and secret settings, and importing such a file keeps the
  ones already there.
- **Upgrade:** replace the binary and start it. New settings get their
  defaults, and `cocosmail init` adds new default files without touching yours.
  Config files of older versions (`COCOSMAIL_KEY=value`) are still read;
  `./cocosmail config convert old.cfg conf/cocosmail.yaml` turns them into YAML
  and warns about mistakes the old version ignored.

## Settings and data

cocosmail keeps two things in its database: **settings** (about 50,
documented in `conf/cocosmail.yaml.base`) and **data** (domains, users,
aliases, relay IPs, routes, DKIM keys). Only `db_driver` and `db_source` stay
outside, since they say where the database is (default: SQLite in `db/`).

One YAML file can hold both:

```yaml
settings:
  me: mail.example.com
  smtpd_launch: true
  smtpd_dsns: '[::]:25:mail.example.com:nossl:example.com'
domains:
  - name: example.com
    local: true
users:
  - login: you@example.com
    password: a-good-password   # hashed when imported
    mailbox: true
    relay: true
aliases:
  - alias: sales@example.com
    deliver_to: [you@example.com, partner@elsewhere.net]
```

- **Database mode** (default): the database is the source of truth.
  `conf/cocosmail.yaml`, if present, is imported at the first start. Then use
  `config edit`, `config set KEY VALUE`, `config import`...
- **File mode** (`--config FILE` or `COCOSMAIL_CONFIG`): the file's settings
  are loaded at every start and are read only elsewhere; change the file and
  restart. Its data is imported only into an empty database. Starting once
  without `--config` goes back to database mode.

`config import` checks everything before writing anything: settings not in the
file get their default (`--merge` keeps them), data is added or changed
(`--replace` also deletes what's not in the file).

### Text UI keys

| Key         | Action                                                       |
|-------------|--------------------------------------------------------------|
| F1          | help                                                         |
| Tab         | switch between the sections and the list                     |
| typing      | search the list, Esc clears                                  |
| Enter, F4   | edit (true/false values are switched)                        |
| F7, Ins     | add a domain, user, alias, relay IP, route or DKIM key       |
| F8, Del     | delete an item, or reset a setting to its default            |
| F6          | DKIM keys: the DNS record to publish                         |
| F3          | show or hide secrets                                         |
| F2          | save, after showing what changed                             |
| F10, Esc    | quit (asks about unsaved changes)                            |

`config edit --file FILE` edits a config file instead, without a database, e.g.
to prepare a server offline. `config get`, `set`, `unset` and `list` also take
`--file`.

## Listeners and outgoing IPs

`smtpd_dsns`, `imapd_dsns` and `pop3d_dsns` are listeners separated by `;`, each
`IP:PORT:HOSTNAME:ssl|nossl:CERT`:

```yaml
  smtpd_dsns: '[::]:25:mail.example.com:nossl:example.com;[::]:587:mail.example.com:nossl:example.com;[::]:465:mail.example.com:ssl:example.com'
  imapd_dsns: '[::]:993:mail.example.com:ssl:example.com'
  pop3d_dsns: '[::]:995:mail.example.com:ssl:example.com'
```

- IP: IPv4, IPv6 in brackets (`[2001:db8::10]`, `[fe80::1%eth0]`), or `[::]`,
  `0.0.0.0` or empty for all addresses, IPv4 and IPv6.
- `ssl`: TLS from the start; `nossl`: plain text with STARTTLS, login only after
  it. POP3 has no STARTTLS, so `nossl` is only allowed there on loopback
  (behind a TLS proxy). IMAP on loopback with `nossl` allows login without TLS.

`deliverd_local_ips` are the addresses used to send mail: `&` between them for
failover, `|` for round robin, `:hostname` for a HELO name per address
(`[2001:db8::10]:mail.example.com`). The default `0.0.0.0&::` uses IPv4 and
falls back to IPv6. Routes use the same syntax.

`config export-dns` gives the A/AAAA records of each listener hostname and
HELO name, and the PTR record of each outgoing address.

## Mail storage

Each user's mail is a Maildir in `mailboxes/`: INBOX is the user's directory
(`cur/`, `new/`, `tmp/`), folders are `.Sent`, `.Archive.2024`... in it
(Maildir++, the layout Dovecot uses), and flags are in the file names. A
mailbox can be backed up, or brought from another server, by copying the
directory. IMAP UIDs are kept in `cocosmail-uidlist` in each folder.

## Command line

`./cocosmail help` and `./cocosmail <command> help` show everything.

| Command    | Purpose                                                              |
|------------|----------------------------------------------------------------------|
| `init`     | default files, database tables, a setup for `--hostname` (safe to repeat) |
| `config`   | `edit`, `list`, `get`, `set`, `unset`, `import`, `export`, `export-dns`, `convert` |
| `rcpthost` | domains cocosmail accepts mail for                                   |
| `user`     | users, mailboxes, catch-all                                          |
| `alias`    | aliases, forwarding, pipe to command                                 |
| `relayip`  | IPs allowed to send without login                                    |
| `routes`   | static routes, e.g. a smarthost                                      |
| `dkim`     | DKIM keys and DNS records                                            |
| `queue`    | outgoing queue: list, discard, bounce, purge                         |

```sh
# send all mail for example.net through a smarthost
./cocosmail routes add -d example.net -rh smtp.provider.net -rp 587 -rl login -rpwd password
```

## Plugins

Plugins are Go source files in `plugins/<name>/<name>.go`, interpreted at
runtime by [yaegi](https://github.com/traefik/yaegi): no Go toolchain needed on
the server. They hook into the SMTP session (`connect`, `helo`, `mailpre`,
`mailpost`, `rcptto`, `data`, `beforequeue`, `quit`, `exitasap`, `auth`), and
`plugins/config.go` enables them. Included: `fail2ban` (bans IPs after failed
logins, on by default) and `customgreeting` (an example).

Plugins can import `bufio`, `encoding/json`, `errors`, `fmt`, `io`, `net`,
`strings`, `time` and cocosmail's `core`. In `data` and `beforequeue`,
`s.RawMail()` opens the message received (close it when done): it's in a file,
not in memory, so read it as a stream.

## More

[TODO.md](TODO.md) has plans and known issues, [CHANGELOG](CHANGELOG) the
history. Issues and pull requests are welcome; feedback on what was hard to
set up is especially useful, since easy setup is the point of this project.

cocosmail started as [tmail](https://github.com/toorop/tmail) by Stéphane
Depierrepont (Toorop). MIT license, see [LICENSE](LICENSE).
