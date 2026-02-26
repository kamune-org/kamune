package main

import (
	"fmt"
	"os"

	"github.com/kamune-org/kamune/relay/cmd/relay/run"
)

// Set via ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Printf("kamune-relay %s (commit: %s, built: %s)\n", version, commit, date)
		return
	}

	if err := run.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
