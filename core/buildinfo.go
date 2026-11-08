package core

import "runtime/debug"

// Commit is the git commit of the build. go build in a git checkout records
// it in the binary; else it can be set with
// -ldflags "-X github.com/stunndard/cocosmail/core.Commit=HASH"
var Commit string

// BuildVersion returns the version and the git commit of the binary, e.g.
// "0.3.0 (commit ab69894, 2026-11-09, modified)". modified: built with
// changes not committed.
func BuildVersion() string {
	commit, date, modified := Commit, "", false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.time":
				date = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	return formatVersion(CocosmailVersion, commit, date, modified)
}

func formatVersion(version, commit, date string, modified bool) string {
	if commit == "" {
		return version + " (commit unknown)"
	}
	if len(commit) > 7 {
		commit = commit[:7]
	}
	s := version + " (commit " + commit
	if len(date) >= 10 {
		s += ", " + date[:10]
	}
	if modified {
		s += ", modified"
	}
	return s + ")"
}
