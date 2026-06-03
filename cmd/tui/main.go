package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

var errCh = make(chan error)
var stop = make(chan struct{})

type Program struct {
	*tea.Program
}

func NewProgram(p *tea.Program) *Program {
	return &Program{Program: p}
}

func main() {
	var dbFlag string
	var passwordFlag string
	flag.StringVar(&dbFlag, "db", "", "path to DB file")
	flag.StringVar(&passwordFlag, "password", "", "relay PSK password")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("usage: ./chat -db <path> -password <psk> <mode> [args...]")
		fmt.Println("modes:")
		fmt.Println("  dial <addr>              Direct TCP dial")
		fmt.Println("  serve <addr>             Direct TCP server")
		fmt.Println("  history <sessionID>      Print chat history")
		fmt.Println("  relay-dial <addr> <token> Dial through relay")
		fmt.Println("  relay-serve <addr>       Serve through relay")
		os.Exit(1)
	}

	mode := args[0]

	switch mode {
	case "dial":
		if len(args) < 2 {
			fmt.Println("usage: dial <addr>")
			os.Exit(1)
		}
		go func() {
			client(args[1])
		}()
	case "serve":
		if len(args) < 2 {
			fmt.Println("usage: serve <addr>")
			os.Exit(1)
		}
		go func() {
			server(args[1])
		}()
	case "history":
		if len(args) < 2 {
			fmt.Println("usage: history <sessionID>")
			os.Exit(1)
		}
		go func() {
			if err := printHistory(args[1], dbFlag); err != nil {
				errCh <- fmt.Errorf("history: %w", err)
			}
			stop <- struct{}{}
		}()
	case "relay-dial":
		if len(args) < 3 {
			fmt.Println("usage: relay-dial <relayAddr> <token>")
			os.Exit(1)
		}
		go func() {
			relayClient(args[1], args[2], passwordFlag)
		}()
	case "relay-serve":
		if len(args) < 2 {
			fmt.Println("usage: relay-serve <relayAddr>")
			os.Exit(1)
		}
		go func() {
			relayServer(args[1], passwordFlag)
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
