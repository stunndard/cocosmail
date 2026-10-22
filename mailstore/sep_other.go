//go:build !windows

package mailstore

import "strings"

// infoSep separates the key of a message file from its flags: key:2,FLAGS
const infoSep = ':'

// hostEscaper escapes the hostname part of keys, as the Maildir spec says
var hostEscaper = strings.NewReplacer("/", `\057`, ":", `\072`)
