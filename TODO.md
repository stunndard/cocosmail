TODO

## Planned
- [ ] Turbo Vision style TUI configurator (https://github.com/unxed/vtui)

## Setup friction
- [ ] First start asks interactively to create DB tables; it panics without stdin (e.g. under systemd). Add an `initdb` command or flag.
- [ ] `dist/ssl` ships `server.crt/key`, but listeners expect `smtp-<cert>.*` / `pop3-<cert>.*`, so a fresh install with the example config fails on POP3.
- [ ] `dist/run` starts `cocosmail32` on anything that isn't x86_64 (breaks arm64).
- [ ] Demo plugin `customgreeting` is enabled by default in `dist/plugins/config.go`, and doesn't compile against the current API (`s.Out` needs a code), so it is silently skipped.
- [ ] Config paths in `cocosmail.cfg.base` are absolute (`/home/cocosmail/dist`); make them relative to the base path.

## Bugs
- [ ] `core/deliverd_remote.go`: SMTP AUTH condition checks `SmtpAuthLogin` twice instead of login and password (go vet).
- [ ] go vet: `QMessage` containing a mutex is copied (`core/deliverd.go`, `core/mailqueue.go`).
- [ ] `rcpthost add -l` help text says "remote host", but the flag marks a local domain.
- [ ] Received header shows `helo=[[...]]` when the client HELOs with an address literal.

## Other
- [ ] Sync nsq/DB in case of crash (requeue in nsq expired messages from DB)
- [ ] More tests
