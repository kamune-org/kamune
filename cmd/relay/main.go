package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
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
	var cfgPath string
	var showVersion bool
	flag.StringVar(&cfgPath, "c", "", "config file path (omit to use "+config.EnvKey+" env var)")
	flag.BoolVar(&showVersion, "v", false, "print version")
	flag.Parse()

	if showVersion {
		fmt.Printf("kamune-relay %s (kamune: %s)\n", version, kamuneVersion())
		return
	}

	if err := run.Run(cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
