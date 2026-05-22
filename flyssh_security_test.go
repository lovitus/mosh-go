//go:build !js

package mosh

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func encryptTestPayload(t *testing.T, sender *Transport, payload []byte) []byte {
	t.Helper()
	sender.mu.Lock()
	sender.seqOut++
	seq := sender.seqOut
	dirSeq := sender.toRemote | (seq & seqMask)
	lastTS := sender.lastTS
	sender.mu.Unlock()

	var dirSeqBytes [8]byte
	binary.BigEndian.PutUint64(dirSeqBytes[:], dirSeq)

	var nonce [12]byte
	copy(nonce[4:], dirSeqBytes[:])

	plaintext := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(plaintext[0:], uint16(time.Now().UnixMilli()&0xffff))
	binary.BigEndian.PutUint16(plaintext[2:], lastTS)
	copy(plaintext[4:], payload)

	tagAndCT := sender.ocb.Encrypt(nonce[:], plaintext)
	wire := make([]byte, 8+len(tagAndCT))
	copy(wire[:8], dirSeqBytes[:])
	copy(wire[8:], tagAndCT)
	return wire
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encryptedFragment(t *testing.T, sender *Transport, f Fragment) []byte {
	t.Helper()
	return encryptTestPayload(t, sender, f.Marshal())
}

func TestTransportRecvResultAuthenticationClasses(t *testing.T) {
	server, client := newTestPair(t)

	if result, err := client.Recv([]byte{1, 2, 3}); err != nil || result.Authenticated {
		t.Fatalf("short packet result=%+v err=%v, want unauthenticated nil error", result, err)
	}

	server.SetPending([]byte("hello"))
	valid := server.Tick()[0]
	if result, err := server.Recv(valid); err != nil || result.Authenticated {
		t.Fatalf("wrong direction result=%+v err=%v, want unauthenticated nil error", result, err)
	}

	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 0xff
	if result, err := client.Recv(tampered); err != nil || result.Authenticated {
		t.Fatalf("bad tag result=%+v err=%v, want unauthenticated nil error", result, err)
	}

	if result, err := client.Recv(valid); err != nil || !result.Authenticated || result.Diff == nil {
		t.Fatalf("valid result=%+v err=%v, want authenticated diff", result, err)
	}
	if result, err := client.Recv(valid); err != nil || result.Authenticated {
		t.Fatalf("replay result=%+v err=%v, want unauthenticated nil error", result, err)
	}
}

func TestTransportRecvResultHeartbeatAndDecodeFailures(t *testing.T) {
	server, client := newTestPair(t)

	heartbeat := encryptTestPayload(t, server, nil)
	if result, err := client.Recv(heartbeat); err != nil || !result.Authenticated || result.Diff != nil {
		t.Fatalf("heartbeat result=%+v err=%v, want authenticated no diff", result, err)
	}

	partial := encryptedFragment(t, server, Fragment{ID: 2, FragmentNum: 0, Payload: []byte("part")})
	if result, err := client.Recv(partial); err != nil || !result.Authenticated || result.Diff != nil {
		t.Fatalf("partial result=%+v err=%v, want authenticated no diff", result, err)
	}

	duplicate := encryptedFragment(t, server, Fragment{ID: 2, FragmentNum: 0, Payload: []byte("part")})
	if result, err := client.Recv(duplicate); err != nil || !result.Authenticated || result.Diff != nil {
		t.Fatalf("duplicate result=%+v err=%v, want authenticated no diff", result, err)
	}

	badZlib := encryptedFragment(t, server, Fragment{ID: 3, FragmentNum: 0, Final: true, Payload: []byte("not zlib")})
	if result, err := client.Recv(badZlib); err == nil || result.Authenticated {
		t.Fatalf("bad zlib result=%+v err=%v, want unauthenticated error", result, err)
	}

	badPB := encryptedFragment(t, server, Fragment{ID: 4, FragmentNum: 0, Final: true, Payload: zlibBytes(t, []byte{0xff})})
	if result, err := client.Recv(badPB); err == nil || result.Authenticated {
		t.Fatalf("bad protobuf result=%+v err=%v, want unauthenticated error", result, err)
	}
}

func TestTransportRecvOversizedFragmentFailsClosed(t *testing.T) {
	server, client := newTestPair(t)

	const id = 9
	var sawErr bool
	for i := 0; i < 900; i++ {
		wire := encryptedFragment(t, server, Fragment{
			ID:          id,
			FragmentNum: uint16(i),
			Payload:     bytes.Repeat([]byte{byte(i)}, maxFragmentPayload),
		})
		result, err := client.Recv(wire)
		if err != nil {
			sawErr = true
			if result.Authenticated {
				t.Fatalf("oversized result=%+v err=%v, want unauthenticated error", result, err)
			}
			break
		}
	}
	if !sawErr {
		t.Fatal("expected oversized fragment error")
	}

	old := encryptedFragment(t, server, Fragment{ID: id, FragmentNum: 1, Final: true, Payload: []byte("old")})
	if result, err := client.Recv(old); err != nil || !result.Authenticated || result.Diff != nil {
		t.Fatalf("old id after reset result=%+v err=%v, want authenticated no diff", result, err)
	}

	server.mu.Lock()
	server.sentNum = id + 1
	server.mu.Unlock()
	server.SetPending([]byte("fresh"))
	var diff []byte
	for _, dg := range server.Tick() {
		if d := recvDiff(t, client, dg); d != nil {
			diff = d
		}
	}
	if !bytes.Equal(diff, []byte("fresh")) {
		t.Fatalf("fresh diff = %q, want fresh", diff)
	}
}

func TestFragmentAssemblerAccountingDuplicateAndOversized(t *testing.T) {
	var a FragmentAssembler

	first := Fragment{ID: 1, FragmentNum: 0, Payload: bytes.Repeat([]byte("a"), 600*1024)}
	if result, err := a.Add(first); err != nil || result != nil {
		t.Fatalf("first result=%v err=%v, want nil nil", result, err)
	}
	if result, err := a.Add(first); err != nil || result != nil {
		t.Fatalf("duplicate result=%v err=%v, want nil nil", result, err)
	}
	second := Fragment{ID: 1, FragmentNum: 1, Final: true, Payload: bytes.Repeat([]byte("b"), 300*1024)}
	if result, err := a.Add(second); err != nil || result == nil {
		t.Fatalf("second result len=%d err=%v, want complete nil err", len(result), err)
	}

	tooLarge := Fragment{ID: 2, FragmentNum: 0, Payload: bytes.Repeat([]byte("x"), maxReassembledSize+1)}
	if result, err := a.Add(tooLarge); err == nil || result != nil {
		t.Fatalf("tooLarge result=%v err=%v, want nil error", result, err)
	}
	if result, err := a.Add(Fragment{ID: 2, FragmentNum: 1, Final: true, Payload: []byte("old")}); err != nil || result != nil {
		t.Fatalf("old id result=%v err=%v, want nil nil", result, err)
	}
	if result, err := a.Add(Fragment{ID: 3, FragmentNum: 0, Final: true, Payload: []byte("new")}); err != nil || !bytes.Equal(result, []byte("new")) {
		t.Fatalf("new id result=%q err=%v, want new", result, err)
	}
}

type packetDatagram struct {
	data []byte
	addr net.Addr
}

type memoryPacketConn struct {
	mu       sync.Mutex
	in       chan packetDatagram
	out      chan packetDatagram
	closed   chan struct{}
	local    net.Addr
	deadline time.Time
}

func newMemoryPacketConn(local net.Addr) *memoryPacketConn {
	return &memoryPacketConn{
		in:     make(chan packetDatagram, 64),
		out:    make(chan packetDatagram, 64),
		closed: make(chan struct{}),
		local:  local,
	}
}

func (c *memoryPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timer <-chan time.Time
	c.mu.Lock()
	if !c.deadline.IsZero() {
		timer = time.After(time.Until(c.deadline))
	}
	c.mu.Unlock()

	select {
	case dg := <-c.in:
		return copy(p, dg.data), dg.addr, nil
	case <-timer:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *memoryPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	data := append([]byte(nil), p...)
	select {
	case c.out <- packetDatagram{data: data, addr: addr}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *memoryPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *memoryPacketConn) LocalAddr() net.Addr { return c.local }

func (c *memoryPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *memoryPacketConn) inject(addr net.Addr, data []byte) {
	c.in <- packetDatagram{addr: addr, data: append([]byte(nil), data...)}
}

func waitForAddr(t *testing.T, srv *Server, want net.Addr, shouldMatch bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		got := srv.clientAddr
		srv.mu.Unlock()
		if shouldMatch {
			if got != nil && got.String() == want.String() {
				return
			}
		} else if got == nil || got.String() != want.String() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.mu.Lock()
	got := srv.clientAddr
	srv.mu.Unlock()
	t.Fatalf("clientAddr=%v, want match=%v addr=%v", got, shouldMatch, want)
}

func TestServerRoamingOnlyUsesAuthenticatedDatagrams(t *testing.T) {
	conn := newMemoryPacketConn(PacketAddr("127.0.0.1:60001"))
	srv, err := NewServerConn("/bin/sh", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	out := make(chan UserInstruction, 8)
	go srv.recvUDP(out)

	attacker := PacketAddr("attacker:1")
	conn.inject(attacker, []byte("not authenticated"))
	waitForAddr(t, srv, attacker, false)

	ocb, err := NewOCB(srv.key)
	if err != nil {
		t.Fatal(err)
	}
	client := NewTransport(ocb, false)
	validAddr := PacketAddr("client:1")

	client.ForceNextSend()
	heartbeat := client.Tick()[0]
	conn.inject(validAddr, heartbeat)
	waitForAddr(t, srv, validAddr, true)

	badAddr := PacketAddr("client:2")
	badZlib := encryptedFragment(t, client, Fragment{ID: 2, FragmentNum: 0, Final: true, Payload: []byte("not zlib")})
	conn.inject(badAddr, badZlib)
	waitForAddr(t, srv, badAddr, false)

	client.mu.Lock()
	client.sentNum = 2
	client.mu.Unlock()
	client.SetPending(marshalUserMessage([]UserInstruction{{Keys: []byte("x")}}))
	for _, dg := range client.Tick() {
		conn.inject(badAddr, dg)
	}
	waitForAddr(t, srv, badAddr, true)
	select {
	case ui := <-out:
		if string(ui.Keys) != "x" {
			t.Fatalf("keys = %q, want x", ui.Keys)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for user instruction")
	}
}

func TestServerTakeoverRequiresFreshKey(t *testing.T) {
	conn := newMemoryPacketConn(PacketAddr("127.0.0.1:60003"))
	srv, err := NewServerConn("/bin/sh", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	out := make(chan UserInstruction, 8)
	go srv.recvUDP(out)

	oldKey := append([]byte(nil), srv.key...)
	oldOCB, err := NewOCB(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldClient := NewTransport(oldOCB, false)
	oldAddr := PacketAddr("old-client:1")
	oldClient.ForceNextSend()
	conn.inject(oldAddr, oldClient.Tick()[0])
	waitForAddr(t, srv, oldAddr, true)

	newKey, err := srv.Takeover()
	if err != nil {
		t.Fatal(err)
	}
	if newKey == "" || newKey == base64.StdEncoding.EncodeToString(oldKey) {
		t.Fatalf("Takeover key = %q, want fresh key", newKey)
	}
	waitForAddr(t, srv, oldAddr, false)

	oldClient.SetPending(marshalUserMessage([]UserInstruction{{Keys: []byte("old")}}))
	for _, dg := range oldClient.Tick() {
		conn.inject(oldAddr, dg)
	}
	waitForAddr(t, srv, oldAddr, false)

	newOCB, err := NewOCB(srv.key)
	if err != nil {
		t.Fatal(err)
	}
	newClient := NewTransport(newOCB, false)
	newAddr := PacketAddr("new-client:1")
	newClient.SetPending(marshalUserMessage([]UserInstruction{{Keys: []byte("new")}}))
	for _, dg := range newClient.Tick() {
		conn.inject(newAddr, dg)
	}
	waitForAddr(t, srv, newAddr, true)
	select {
	case ui := <-out:
		if string(ui.Keys) != "new" {
			t.Fatalf("keys = %q, want new", ui.Keys)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for new client instruction")
	}
}

func TestServerNetworkTimeoutConfig(t *testing.T) {
	conn := newMemoryPacketConn(PacketAddr("127.0.0.1:60004"))
	srv, err := NewServerConn("/bin/sh", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.SetNetworkTimeout(14 * 24 * time.Hour)
	if got := srv.idleNetworkTimeout(); got != 14*24*time.Hour {
		t.Fatalf("idleNetworkTimeout = %v, want 14 days", got)
	}
	srv.SetNetworkTimeout(0)
	if got := srv.idleNetworkTimeout(); got != defaultNetworkTimeout {
		t.Fatalf("idleNetworkTimeout = %v, want default %v", got, defaultNetworkTimeout)
	}
}

func TestNewServerConnUsesInjectedLocalAddr(t *testing.T) {
	conn := newMemoryPacketConn(PacketAddr("127.0.0.1:61234"))
	srv, err := NewServerConn("/bin/sh", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if got, want := srv.Port(), 61234; got != want {
		t.Fatalf("Port() = %d, want %d", got, want)
	}
	if got := srv.ConnectLine(); !bytes.Contains([]byte(got), []byte(" 61234 ")) {
		t.Fatalf("ConnectLine() = %q, want injected port", got)
	}
}

func TestServeConnReplacesPacketConn(t *testing.T) {
	original := newMemoryPacketConn(PacketAddr("127.0.0.1:60000"))
	srv, err := NewServerConn("/bin/sh", original)
	if err != nil {
		t.Fatal(err)
	}
	injected := newMemoryPacketConn(PacketAddr("127.0.0.1:60002"))

	go func() {
		_ = srv.ServeConn(injected)
	}()
	defer func() {
		srv.Close()
	}()

	// ServeConn should synchronously replace the connection before Serve starts
	// the shell. Poll briefly because Serve starts in a goroutine.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if srv.Port() == 60002 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Port() != 60002 {
		t.Fatalf("Port() = %d, want replacement conn port 60002", srv.Port())
	}
}

var _ PacketConn = (*memoryPacketConn)(nil)
var _ net.Error = deadlineError{}

type deadlineError struct{}

func (deadlineError) Error() string   { return os.ErrDeadlineExceeded.Error() }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }

func TestMemoryPacketConnDeadline(t *testing.T) {
	conn := newMemoryPacketConn(PacketAddr("127.0.0.1:1"))
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	_, _, err := conn.ReadFrom(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom err=%v, want deadline", err)
	}
}
