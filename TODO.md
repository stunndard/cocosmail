TODO

## Planned
- [x] Turbo Vision style TUI configurator (https://github.com/unxed/vtui)
- [x] Domains, users, aliases, relay IPs, routes and DKIM keys in the configurator, and with settings in one YAML file (`config export/import`)
- [ ] DKIM keys are 1024-bit RSA; 2048 is recommended today, but its DNS record must be split in 255-char strings
- [ ] `User.Active` is never checked and the mailbox quota is stored but not enforced (not shown in the configurator)

## Setup friction
- [x] First start asks interactively to create DB tables; it panics without stdin (e.g. under systemd). Added `cocosmail init`.
- [ ] `dist/ssl` ships `server.crt/key`, but listeners expect `smtp-<cert>.*` / `pop3-<cert>.*`, so a fresh install with the example config fails on POP3.
- [x] `dist/run` starts `cocosmail32` on anything that isn't x86_64 (breaks arm64).
- [x] Demo plugin `customgreeting` is enabled by default in `dist/plugins/config.go`, and doesn't compile against the current API (`s.Out` needs a code), so it is silently skipped.
- [x] Config paths in `cocosmail.cfg.base` are absolute (`/home/cocosmail/dist`); make them relative to the binary directory.

## Bugs
- [ ] `core/deliverd_remote.go`: SMTP AUTH condition checks `SmtpAuthLogin` twice instead of login and password (go vet).
- [ ] go vet: `QMessage` containing a mutex is copied (`core/deliverd.go`, `core/mailqueue.go`).
- [ ] `rcpthost add -l` help text says "remote host", but the flag marks a local domain.
- [ ] Received header shows `helo=[[...]]` when the client HELOs with an address literal.
- [x] MAIL FROM accepted malformed addresses: `<`, several `@`, no local part (issue #2).

## Other
- [ ] Sync nsq/DB in case of crash (requeue in nsq expired messages from DB)
- [ ] More tests
