package internal

import (
	"github.com/stunndard/cocosmail/imap/goimap"
)

func FormatRights(rm imap.RightModification, rs imap.RightSet) string {
	s := ""
	if rm != imap.RightModificationReplace {
		s = string(rm)
	}
	return s + string(rs)
}
