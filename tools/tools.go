//go:build tools

// Package tools pins build-time tool dependencies (gomobile bind).
package tools

import (
	_ "golang.org/x/mobile/bind"
)
