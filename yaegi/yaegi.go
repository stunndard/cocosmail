// Package yaegi holds the symbols plugins can import. The core ones are
// extracted again after the API of core changes:
//
//	go generate ./yaegi
//
// The test checks that a plugin using the session API loads.
package yaegi

//go:generate go run github.com/traefik/yaegi/cmd/yaegi extract -name yaegi github.com/stunndard/cocosmail/core

import "reflect"

// Symbols variable stores the map of stdlib symbols per package.
var Symbols = map[string]map[string]reflect.Value{}
