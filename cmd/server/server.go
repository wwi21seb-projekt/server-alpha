// Package main is the entry point of the server-alpha application.
// It sets up and starts the server by calling initialization functions from the internal package.
package main

import (
	"github.com/wwi21seb-projekt/server-alpha/internal"
)

// Main is the entry point of the application.
// It calls the Init function from the internal package to set up and start the server.
func main() {
	internal.Init()
}
