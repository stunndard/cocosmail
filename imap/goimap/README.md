# goimap

IMAP library used by cocosmail's imapd: the `imap`, `imapserver` and
`internal` packages of [emersion/go-imap](https://github.com/emersion/go-imap)
v2.0.0-beta.8, maintained here as part of cocosmail. MIT license, see
[LICENSE](LICENSE).

Changes:
- `Conn.SetDebug` (imapserver/debug.go): a protocol log for each connection,
  client and server sides apart, also after STARTTLS.
