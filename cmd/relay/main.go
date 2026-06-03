package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/kamune-org/kamune/cmd/relay/run"
)

var (
	version = "dev"
)

func kamuneVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/kamune-org/kamune" {
			return dep.Version
		}
	}
	return "unknown"
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Printf("kamune-relay %s (kamune: %s)\n", version, kamuneVersion())
		return
	}

	if err := run.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
