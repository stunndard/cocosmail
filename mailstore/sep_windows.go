package mailstore

import "strings"

// infoSep separates the key of a message file from its flags. Windows doesn't
// allow ":" in file names: key;2,FLAGS, as older cocosmail versions (the
// go-maildir library) wrote them.
const infoSep = ';'

// hostEscaper keeps the hostname part of keys a plain file name: \ separates
// paths on Windows
var hostEscaper = strings.NewReplacer("/", "_", `\`, "_", ":", "_", ";", "_")
