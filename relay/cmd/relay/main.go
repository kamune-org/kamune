package main

import (
	"fmt"
	"os"

	"github.com/kamune-org/kamune/relay/cmd/relay/run"
)

func main() {
	if err := run.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
