// Package dist holds the files cocosmail needs next to its binary. They're
// embedded in the binary, cocosmail init writes the missing ones.
package dist

import "embed"

// Files are the default files, paths relative to the binary directory
//
//go:embed conf/cocosmail.yaml.base plugins tpl ssl/README.txt
var Files embed.FS
