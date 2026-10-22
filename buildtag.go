//go:build !goffi_static

package main

// vtui (TUI configurator) uses goffi, which doesn't link in cgo builds (sqlite
// needs cgo). With the goffi_static tag it links: the configurator only needs
// the terminal, not goffi. Build with: go build -tags goffi_static
var _ = build_with_go_build_tags_goffi_static
