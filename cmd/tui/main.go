package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
)

var errCh = make(chan error)
var stop = make(chan struct{})

type Program struct {
	*tea.Program
	transport *kamune.Transport
}

func NewProgram(p *tea.Program) *Program {
	return &Program{Program: p}
}

func main() {
	var dbFlag string
	flag.StringVar(&dbFlag, "db", "", "path to DB file")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		fmt.Println("expected 2 args: [mode] [addr|sessionID]")
		fmt.Println("modes: dial, serve, history")
		fmt.Println("example: ./chat -db ./client.db dial 127.0.0.1:9000")
		os.Exit(1)
	}

	mode := args[0]
	arg := args[1]

	switch mode {
	case "dial":
		go func() {
			client(arg)
		}()
	case "serve":
		go func() {
			server(arg)
		}()
	case "history":
		go func() {
			// Treat arg as the session ID to inspect.
			sid := arg
			if err := printHistory(sid, dbFlag); err != nil {
				errCh <- fmt.Errorf("history: %w", err)
			}
			stop <- struct{}{}
		}()
	default:
		panic(fmt.Errorf("invalid command: %s", mode))
	}

	select {
	case err := <-errCh:
		fmt.Println("error:", err)
	case <-stop:
	}
}

type Message struct {
	prefix string
	text   string
}

func NewMessage(timestamp time.Time, text []byte) Message {
	return Message{
		prefix: fmt.Sprintf("[%s] Peer: ", timestamp.Format(time.DateTime)),
		text:   string(text),
	}
}
