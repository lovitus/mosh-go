//go:build !js

package mosh

import (
	"bytes"
	"testing"
	"time"

	"github.com/unixshells/vt-go"
)

type terminalResponseWriter struct {
	ch chan []byte
}

func (w terminalResponseWriter) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	w.ch <- cp
	return len(p), nil
}

func TestForwardTerminalResponsesUnblocksTerminalQueries(t *testing.T) {
	srv := &Server{
		emu:  vt.NewEmulator(80, 24),
		done: make(chan struct{}),
	}
	defer srv.closeEmulator()
	defer close(srv.done)

	responses := make(chan []byte, 1)
	go srv.forwardTerminalResponses(terminalResponseWriter{ch: responses})

	writeDone := make(chan error, 1)
	go func() {
		_, err := srv.emu.Write([]byte("\x1b[6n"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("emulator write failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal query blocked because emulator responses were not drained")
	}

	select {
	case got := <-responses:
		if !bytes.Contains(got, []byte("\x1b[1;1R")) {
			t.Fatalf("terminal response = %q, want cursor position report", got)
		}
	case <-time.After(time.Second):
		t.Fatal("did not forward terminal query response")
	}
}
