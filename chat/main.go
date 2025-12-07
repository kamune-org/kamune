package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
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

func serveHandler(t *kamune.Transport) error {
	p := NewProgram(tea.NewProgram(initialModel(t), tea.WithAltScreen()))
	go func() {
		if _, err := p.Run(); err != nil {
			panic(err)
		}
		stop <- struct{}{}
	}()

	for {
		b := kamune.Bytes(nil)
		metadata, err := t.Receive(b)
		if err != nil {
			if errors.Is(err, kamune.ErrConnClosed) {
				p.Quit()
				return nil
			}
			errCh <- fmt.Errorf("receiving: %w", err)
			return nil
		}
		p.Send(NewMessage(metadata.Timestamp(), b.GetValue()))
		go func() {
			t.Store().AddChatEntry(
				t.SessionID(),
				b.GetValue(),
				metadata.Timestamp(),
				true,
			)
		}()
	}
}

func server(addr string) {
	var opts []kamune.StorageOption
	opts = append(
		opts,
		kamune.StorageWithDBPath("./server.db"),
		kamune.StorageWithNoPassphrase(),
	)

	srv, err := kamune.NewServer(
		addr,
		serveHandler,
		kamune.ServeWithStorageOpts(opts...),
	)
	if err != nil {
		errCh <- fmt.Errorf("starting server: %w", err)
		return
	}
	fp := strings.Join(fingerprint.Emoji(srv.PublicKey().Marshal()), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)
	fmt.Printf("Starting server on %s\n", addr)
	errCh <- srv.ListenAndServe()
}

func client(addr string) {
	var dialOpts []kamune.StorageOption
	dialOpts = append(
		dialOpts,
		kamune.StorageWithDBPath("./client.db"),
		kamune.StorageWithNoPassphrase(),
	)

	dialer, err := kamune.NewDialer(
		addr,
		kamune.DialWithStorageOpts(dialOpts...),
	)
	if err != nil {
		errCh <- fmt.Errorf("create new dialer: %w", err)
		return
	}
	fp := strings.Join(fingerprint.Emoji(dialer.PublicKey().Marshal()), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)

	var t *kamune.Transport
	for {
		var opErr *net.OpError
		var err error
		t, err = dialer.Dial()
		if err == nil {
			break
		}
		if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("dial err: %v", err)
		time.Sleep(5 * time.Second)
	}
	defer t.Close()

	p := NewProgram(tea.NewProgram(initialModel(t), tea.WithAltScreen()))
	go func() {
		if _, err := p.Run(); err != nil {
			errCh <- err
		}
		stop <- struct{}{}
	}()

	for {
		b := kamune.Bytes(nil)
		metadata, err := t.Receive(b)
		if err != nil {
			if errors.Is(err, kamune.ErrConnClosed) {
				p.Quit()
				return
			}
			errCh <- fmt.Errorf("receiving: %w", err)
			return
		}
		p.Send(NewMessage(metadata.Timestamp(), b.GetValue()))
		go func() {
			t.Store().AddChatEntry(
				t.SessionID(), b.GetValue(), metadata.Timestamp(), true,
			)
		}()
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

// printHistory opens a local Bolt DB (preferring ./client.db then ./server.db),
// reads chat entries for the provided session ID, and prints timestamps + message
// payloads to stdout.
func printHistory(sessionID, dbPath string) error {
	if dbPath == "" {
		return fmt.Errorf("db path must be provided with -db flag")
	}

	var entries []kamune.ChatEntry
	// Open kamune.Storage and get chat history.
	s, err := kamune.OpenStorage(
		kamune.StorageWithDBPath(dbPath),
		kamune.StorageWithNoPassphrase(),
	)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer s.Close()

	entries, err = s.GetChatHistory(sessionID)
	if err != nil {
		return fmt.Errorf("getting chat history: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("no chat entries found for session:", sessionID)
		return nil
	}

	for _, ent := range entries {
		sender := "You"
		if !ent.SentByLocal {
			sender = "Peer"
		}
		fmt.Printf(
			"%s: %s  %s\n",
			sender,
			ent.Timestamp.Format(time.DateTime),
			string(ent.Data),
		)
	}

	return nil
}
