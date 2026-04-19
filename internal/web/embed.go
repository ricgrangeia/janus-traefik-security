package web

import "embed"

// StaticFS holds the embedded dashboard files.
// The "static" prefix is stripped by the HTTP file server in cmd/janus/main.go.
//
//go:embed static
var StaticFS embed.FS
