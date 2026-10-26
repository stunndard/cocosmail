TODO

## Planned
- [x] Turbo Vision style TUI configurator (https://github.com/unxed/vtui)
- [x] Domains, users, aliases, relay IPs, routes and DKIM keys in the configurator, and with settings in one YAML file (`config export/import`)
- [ ] DKIM keys are 1024-bit RSA; 2048 is recommended today, but its DNS record must be split in 255-char strings
- [x] IMAP server (go-imap v2, kept in imap/goimap), on the same Maildir as POP3, with Maildir++ folders
- [ ] IMAP: full-text SEARCH reads every message (no index); no CONDSTORE/QRESYNC, QUOTA, CREATE-SPECIAL-USE; at most 26 keywords per folder (Dovecot's scheme); failed IMAP/POP3 logins are not banned like SMTP AUTH (fail2ban plugin hooks are smtpd only)
- [ ] `User.Active` is never checked and the mailbox quota is stored but not enforced (not shown in the configurator)

## Setup friction
- [x] First start asks interactively to create DB tables; it panics without stdin (e.g. under systemd). Added `cocosmail init`.
- [ ] `dist/ssl` ships `server.crt/key`, but listeners expect `smtp-<cert>.*` / `pop3-<cert>.*` / `imap-<cert>.*`, so a fresh install with the example config fails on POP3 and IMAP.
- [x] `dist/run` starts `cocosmail32` on anything that isn't x86_64 (breaks arm64).
- [x] Demo plugin `customgreeting` is enabled by default in `dist/plugins/config.go`, and doesn't compile against the current API (`s.Out` needs a code), so it is silently skipped.
- [x] Config paths in `cocosmail.cfg.base` are absolute (`/home/cocosmail/dist`); make them relative to the binary directory.

## Bugs
- [ ] `core/deliverd_remote.go`: SMTP AUTH condition checks `SmtpAuthLogin` twice instead of login and password (go vet).
- [ ] go vet: `QMessage` containing a mutex is copied (`core/deliverd.go`, `core/mailqueue.go`).
- [ ] `rcpthost add -l` help text says "remote host", but the flag marks a local domain.
- [ ] Received header shows `helo=[[...]]` when the client HELOs with an address literal.
- [x] MAIL FROM accepted malformed addresses: `<`, several `@`, no local part (issue #2).
- [x] `smtpd_max_databytes` 0 (the default, "unlimited") refused every message at DATA.

## Other
- [ ] Sync nsq/DB in case of crash (requeue in nsq expired messages from DB)
- [ ] More tests
