package mosh

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

func newTestPair(t *testing.T) (*Transport, *Transport) {
	t.Helper()
	key := make([]byte, 16)
	rand.Read(key)
	ocbS, err := NewOCB(key)
	if err != nil {
		t.Fatal(err)
	}
	ocbC, err := NewOCB(key)
	if err != nil {
		t.Fatal(err)
	}
	server := NewTransport(ocbS, true)
	client := NewTransport(ocbC, false)
	return server, client
}

func recvDiff(t *testing.T, transport *Transport, wire []byte) []byte {
	t.Helper()
	result, err := transport.Recv(wire)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !result.Authenticated {
		return nil
	}
	return result.Diff
}

func decodeInstructionFromWire(t *testing.T, receiver *Transport, wire []byte) TransportInstruction {
	t.Helper()
	if len(wire) < minDatagram {
		t.Fatalf("wire too short: %d", len(wire))
	}
	var nonce [12]byte
	copy(nonce[4:], wire[:8])
	plaintext := receiver.ocb.Decrypt(nonce[:], wire[8:])
	if plaintext == nil {
		t.Fatal("decrypt failed")
	}
	if len(plaintext) < 4+fragmentHeaderSize {
		t.Fatalf("plaintext too short: %d", len(plaintext))
	}
	frag, err := UnmarshalFragment(plaintext[4:])
	if err != nil {
		t.Fatal(err)
	}
	if frag.FragmentNum != 0 || !frag.Final {
		t.Fatalf("expected one complete fragment, got num=%d final=%v", frag.FragmentNum, frag.Final)
	}
	decompressed := zlibDecompress(frag.Payload)
	if decompressed == nil {
		t.Fatal("decompress failed")
	}
	var ti TransportInstruction
	if err := ti.Unmarshal(decompressed); err != nil {
		t.Fatal(err)
	}
	return ti
}

func encryptTransportPayloadForTest(t *testing.T, sender *Transport, payload []byte) []byte {
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

func wireInstructionForTest(t *testing.T, sender *Transport, fragmentID uint64, ti TransportInstruction) []byte {
	t.Helper()
	frag := Fragment{
		ID:          fragmentID,
		FragmentNum: 0,
		Final:       true,
		Payload:     zlibCompress(ti.Marshal()),
	}
	return encryptTransportPayloadForTest(t, sender, frag.Marshal())
}

func TestTransportBasicExchange(t *testing.T) {
	server, client := newTestPair(t)

	// Server sends a diff.
	server.SetPending([]byte("hello from server"))
	datagrams := server.Tick()
	if len(datagrams) == 0 {
		t.Fatal("no datagrams")
	}

	// Client receives.
	var diff []byte
	for _, dg := range datagrams {
		if d := recvDiff(t, client, dg); d != nil {
			diff = d
		}
	}
	if !bytes.Equal(diff, []byte("hello from server")) {
		t.Fatalf("diff = %q", diff)
	}

	// Client sends a diff.
	client.SetPending([]byte("hello from client"))
	datagrams = client.Tick()
	if len(datagrams) == 0 {
		t.Fatal("no datagrams")
	}

	// Server receives.
	diff = nil
	for _, dg := range datagrams {
		if d := recvDiff(t, server, dg); d != nil {
			diff = d
		}
	}
	if !bytes.Equal(diff, []byte("hello from client")) {
		t.Fatalf("diff = %q", diff)
	}
}

func TestTransportReplayRejected(t *testing.T) {
	server, client := newTestPair(t)

	server.SetPending([]byte("data"))
	datagrams := server.Tick()

	// First receive works.
	if d := recvDiff(t, client, datagrams[0]); d == nil {
		t.Fatal("first receive failed")
	}

	// Replay should be rejected.
	if d := recvDiff(t, client, datagrams[0]); d != nil {
		t.Fatal("replay should be rejected")
	}
}

func TestTransportWrongDirection(t *testing.T) {
	server, _ := newTestPair(t)

	server.SetPending([]byte("data"))
	datagrams := server.Tick()

	// Server receiving its own datagram (wrong direction).
	if d := recvDiff(t, server, datagrams[0]); d != nil {
		t.Fatal("wrong direction should be rejected")
	}
}

func TestTransportLargePayload(t *testing.T) {
	server, client := newTestPair(t)

	// Payload larger than one fragment.
	payload := make([]byte, maxFragmentPayload*3+42)
	rand.Read(payload)

	server.SetPending(payload)
	datagrams := server.Tick()
	if len(datagrams) < 2 {
		t.Fatalf("expected multiple datagrams, got %d", len(datagrams))
	}

	var diff []byte
	for _, dg := range datagrams {
		if d := recvDiff(t, client, dg); d != nil {
			diff = d
		}
	}
	if !bytes.Equal(diff, payload) {
		t.Fatal("large payload mismatch")
	}
}

func TestTransportHeartbeat(t *testing.T) {
	server, _ := newTestPair(t)

	// Force lastSend to be old enough to trigger heartbeat.
	server.mu.Lock()
	server.lastSend = time.Now().Add(-2 * server.rto)
	server.mu.Unlock()

	datagrams := server.Tick()
	if len(datagrams) == 0 {
		t.Fatal("expected heartbeat datagram")
	}
}

func TestTransportThrowawayNumAdvancesAfterAckedSentState(t *testing.T) {
	server, client := newTestPair(t)

	server.SetPending([]byte("one"))
	first := server.Tick()
	if len(first) == 0 {
		t.Fatal("no first datagram")
	}
	if ti := decodeInstructionFromWire(t, client, first[0]); ti.ThrowawayNum != 0 {
		t.Fatalf("initial throwaway = %d, want 0", ti.ThrowawayNum)
	}
	for _, dg := range first {
		recvDiff(t, client, dg)
	}

	ack := client.Tick()
	if len(ack) == 0 {
		t.Fatal("no ack datagram")
	}
	for _, dg := range ack {
		recvDiff(t, server, dg)
	}

	server.SetPending([]byte("two"))
	second := server.Tick()
	if len(second) == 0 {
		t.Fatal("no second datagram")
	}
	ti := decodeInstructionFromWire(t, client, second[0])
	if ti.ThrowawayNum != 1 {
		t.Fatalf("throwaway = %d, want 1", ti.ThrowawayNum)
	}
}

func TestTransportThrowawayNumDoesNotDiscardPendingBase(t *testing.T) {
	server, client := newTestPair(t)

	server.SetPending([]byte("one"))
	first := server.Tick()
	if len(first) == 0 {
		t.Fatal("no first datagram")
	}
	server.SetPending([]byte("two"))
	second := server.Tick()
	if len(second) == 0 {
		t.Fatal("no second datagram")
	}
	if ti := decodeInstructionFromWire(t, client, second[0]); ti.OldNum != 0 || ti.ThrowawayNum != 0 {
		t.Fatalf("second old=%d throwaway=%d, want 0/0", ti.OldNum, ti.ThrowawayNum)
	}

	for _, dg := range first {
		recvDiff(t, client, dg)
	}
	ack := client.Tick()
	if len(ack) == 0 {
		t.Fatal("no ack datagram")
	}
	for _, dg := range ack {
		recvDiff(t, server, dg)
	}

	server.ForceNextSend()
	retry := server.Tick()
	if len(retry) == 0 {
		t.Fatal("no retry datagram")
	}
	ti := decodeInstructionFromWire(t, client, retry[0])
	if ti.OldNum != 0 || ti.ThrowawayNum != 0 {
		t.Fatalf("retry old=%d throwaway=%d, want 0/0", ti.OldNum, ti.ThrowawayNum)
	}
}

func TestTransportRejectsProtocolVersionMismatch(t *testing.T) {
	server, client := newTestPair(t)

	wire := wireInstructionForTest(t, server, 1, TransportInstruction{
		ProtocolVersion: moshProtocolVersion + 1,
		OldNum:          0,
		NewNum:          1,
		AckNum:          7,
		Diff:            []byte("bad-version"),
	})
	result, err := client.Recv(wire)
	if err == nil {
		t.Fatal("expected protocol version error")
	}
	if result.Authenticated || result.Diff != nil {
		t.Fatalf("result=%+v, want unauthenticated no diff", result)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if client.ackedByRemote != 0 {
		t.Fatalf("ackedByRemote = %d, want 0", client.ackedByRemote)
	}
	if len(client.receivedNums) != 1 || client.receivedNums[0] != 0 {
		t.Fatalf("receivedNums = %v, want [0]", client.receivedNums)
	}
}

func TestTransportAckNumDoesNotRegressForOutOfOrderState(t *testing.T) {
	server, client := newTestPair(t)

	wire := wireInstructionForTest(t, server, 1, TransportInstruction{
		ProtocolVersion: moshProtocolVersion,
		OldNum:          0,
		NewNum:          6,
		Diff:            []byte("six"),
	})
	if result, err := client.Recv(wire); err != nil || !bytes.Equal(result.Diff, []byte("six")) {
		t.Fatalf("state 6 result=%+v err=%v", result, err)
	}
	client.mu.Lock()
	if client.ackNum != 6 {
		t.Fatalf("ackNum after state 6 = %d, want 6", client.ackNum)
	}
	client.mu.Unlock()

	wire = wireInstructionForTest(t, server, 2, TransportInstruction{
		ProtocolVersion: moshProtocolVersion,
		OldNum:          0,
		NewNum:          5,
		Diff:            []byte("five"),
	})
	if result, err := client.Recv(wire); err != nil || !bytes.Equal(result.Diff, []byte("five")) {
		t.Fatalf("state 5 result=%+v err=%v", result, err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if client.ackNum != 6 {
		t.Fatalf("ackNum after out-of-order state 5 = %d, want 6", client.ackNum)
	}
	want := []uint64{0, 5, 6}
	if !equalUint64s(client.receivedNums, want) {
		t.Fatalf("receivedNums = %v, want %v", client.receivedNums, want)
	}
}

func TestTransportReceiverQueueFullRejectsNewStateWithoutDroppingOld(t *testing.T) {
	server, client := newTestPair(t)

	full := make([]uint64, maxReceivedStates+1)
	for i := range full {
		full[i] = uint64(i)
	}
	client.mu.Lock()
	client.receivedNums = full
	client.ackNum = uint64(maxReceivedStates)
	client.receiverQuenchUntil = time.Now().Add(receiverQuenchInterval)
	client.mu.Unlock()

	wire := wireInstructionForTest(t, server, 1, TransportInstruction{
		ProtocolVersion: moshProtocolVersion,
		OldNum:          0,
		NewNum:          maxReceivedStates + 1,
		Diff:            []byte("overflow"),
	})
	result, err := client.Recv(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Authenticated || result.Diff != nil {
		t.Fatalf("result=%+v, want authenticated no diff", result)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.receivedNums) != maxReceivedStates+1 {
		t.Fatalf("len(receivedNums) = %d, want %d", len(client.receivedNums), maxReceivedStates+1)
	}
	if client.receivedNums[0] != 0 || client.receivedNums[len(client.receivedNums)-1] != maxReceivedStates {
		t.Fatalf("receivedNums endpoints = %d/%d, want 0/%d", client.receivedNums[0], client.receivedNums[len(client.receivedNums)-1], maxReceivedStates)
	}
	if client.ackNum != maxReceivedStates {
		t.Fatalf("ackNum = %d, want %d", client.ackNum, maxReceivedStates)
	}
}

func TestTransportReceiverQueueOverLimitAllowsOneStateWhenQuenchExpired(t *testing.T) {
	server, client := newTestPair(t)

	full := make([]uint64, maxReceivedStates+1)
	for i := range full {
		full[i] = uint64(i)
	}
	client.mu.Lock()
	client.receivedNums = full
	client.ackNum = uint64(maxReceivedStates)
	client.receiverQuenchUntil = time.Now().Add(-time.Second)
	client.mu.Unlock()

	wire := wireInstructionForTest(t, server, 1, TransportInstruction{
		ProtocolVersion: moshProtocolVersion,
		OldNum:          0,
		NewNum:          maxReceivedStates + 1,
		Diff:            []byte("overflow"),
	})
	beforeRecv := time.Now()
	result, err := client.Recv(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Authenticated || !bytes.Equal(result.Diff, []byte("overflow")) {
		t.Fatalf("result=%+v, want authenticated overflow diff", result)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.receivedNums) != maxReceivedStates+2 {
		t.Fatalf("len(receivedNums) = %d, want %d", len(client.receivedNums), maxReceivedStates+2)
	}
	if client.receivedNums[len(client.receivedNums)-1] != maxReceivedStates+1 {
		t.Fatalf("newest received = %d, want %d", client.receivedNums[len(client.receivedNums)-1], maxReceivedStates+1)
	}
	if client.ackNum != maxReceivedStates+1 {
		t.Fatalf("ackNum = %d, want %d", client.ackNum, maxReceivedStates+1)
	}
	if !client.receiverQuenchUntil.After(beforeRecv) {
		t.Fatal("receiverQuenchUntil was not advanced")
	}
}

func equalUint64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTransportSentStateOverflowCullsMiddleLikeMosh(t *testing.T) {
	tp := &Transport{sentStateNums: []uint64{0}}
	for i := uint64(1); i <= 32; i++ {
		tp.addSentStateLocked(i)
	}

	if len(tp.sentStateNums) != 32 {
		t.Fatalf("len = %d, want 32", len(tp.sentStateNums))
	}
	if tp.sentStateNums[0] != 0 {
		t.Fatalf("oldest = %d, want 0", tp.sentStateNums[0])
	}
	if tp.sentStateNums[len(tp.sentStateNums)-1] != 32 {
		t.Fatalf("newest = %d, want 32", tp.sentStateNums[len(tp.sentStateNums)-1])
	}
	for _, n := range tp.sentStateNums {
		if n == 17 {
			t.Fatal("state 17 should have been culled from the middle")
		}
	}
}

func TestTransportEmptyTick(t *testing.T) {
	server, _ := newTestPair(t)

	// No pending diff, recent send, no ack needed — should produce nothing.
	datagrams := server.Tick()
	if len(datagrams) != 0 {
		t.Fatalf("expected no datagrams, got %d", len(datagrams))
	}
}

func TestTransportRTOBounds(t *testing.T) {
	server, _ := newTestPair(t)

	rto := server.RTO()
	if rto < minRTO || rto > maxRTO {
		t.Fatalf("RTO = %v, not in [%v, %v]", rto, minRTO, maxRTO)
	}
}

func TestTransportMultipleExchanges(t *testing.T) {
	server, client := newTestPair(t)

	for i := 0; i < 10; i++ {
		payload := make([]byte, 100)
		rand.Read(payload)

		server.SetPending(payload)
		for _, dg := range server.Tick() {
			recvDiff(t, client, dg)
		}

		client.SetPending(payload)
		for _, dg := range client.Tick() {
			recvDiff(t, server, dg)
		}
	}

	// Verify sequence numbers advanced.
	server.mu.Lock()
	if server.sentNum < 10 {
		t.Fatalf("sentNum = %d", server.sentNum)
	}
	server.mu.Unlock()
}

// TestTransportCompressionBomb verifies that a zlib-compressed payload
// expanding to >1 MiB is rejected without crashing.
func TestTransportCompressionBomb(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	ocbS, err := NewOCB(key)
	if err != nil {
		t.Fatal(err)
	}
	ocbC, err := NewOCB(key)
	if err != nil {
		t.Fatal(err)
	}
	server := NewTransport(ocbS, true)
	client := NewTransport(ocbC, false)

	// Create a zlib payload that expands to >1 MiB (zeros compress very well).
	bigPayload := make([]byte, 2<<20) // 2 MiB of zeros
	var zbuf bytes.Buffer
	w := zlib.NewWriter(&zbuf)
	w.Write(bigPayload)
	w.Close()
	compressed := zbuf.Bytes()

	// Wrap in a single fragment (final=true, fragment_num=0, id=1).
	var fragWire []byte
	fragWire = make([]byte, fragmentHeaderSize+len(compressed))
	binary.BigEndian.PutUint64(fragWire[0:], 1)                          // id
	binary.BigEndian.PutUint16(fragWire[8:], fragmentFinalBit|uint16(0)) // final, frag 0
	copy(fragWire[fragmentHeaderSize:], compressed)

	// Encrypt as a server->client datagram.
	server.mu.Lock()
	server.seqOut++
	seq := server.seqOut
	dirSeq := dirToClient | (seq & seqMask)
	var dirSeqBytes [8]byte
	binary.BigEndian.PutUint64(dirSeqBytes[:], dirSeq)
	var nonce [12]byte
	copy(nonce[4:], dirSeqBytes[:])

	ts := uint16(time.Now().UnixMilli() & 0xffff)
	plaintext := make([]byte, 4+len(fragWire))
	binary.BigEndian.PutUint16(plaintext[0:], ts)
	binary.BigEndian.PutUint16(plaintext[2:], 0)
	copy(plaintext[4:], fragWire)
	server.mu.Unlock()

	tagAndCT := ocbS.Encrypt(nonce[:], plaintext)
	wire := make([]byte, 8+len(tagAndCT))
	copy(wire[:8], dirSeqBytes[:])
	copy(wire[8:], tagAndCT)

	// Client should reject the bomb before exposing a diff.
	result, err := client.Recv(wire)
	if err == nil {
		t.Fatal("compression bomb should return an error")
	}
	if result.Authenticated || result.Diff != nil {
		t.Fatalf("compression bomb result=%+v, want unauthenticated no diff", result)
	}
}

func TestZlibDecompressRejectsOversizeAndBadChecksum(t *testing.T) {
	var ok bytes.Buffer
	w := zlib.NewWriter(&ok)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := zlibDecompress(ok.Bytes()); !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("valid zlib = %q, want hello", got)
	}

	badChecksum := append([]byte(nil), ok.Bytes()...)
	badChecksum[len(badChecksum)-1] ^= 0xff
	if got := zlibDecompress(badChecksum); got != nil {
		t.Fatalf("bad checksum decoded %d bytes", len(got))
	}

	var oversized bytes.Buffer
	w = zlib.NewWriter(&oversized)
	if _, err := w.Write(bytes.Repeat([]byte{0}, (1<<20)+1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := zlibDecompress(oversized.Bytes()); got != nil {
		t.Fatalf("oversized decoded %d bytes", len(got))
	}
}

// TestTransportConcurrentSendRecv launches multiple goroutines sending
// from the client and receiving on the server simultaneously to verify
// there are no data races under -race.
func TestTransportConcurrentSendRecv(t *testing.T) {
	server, client := newTestPair(t)

	const numGoroutines = 10
	errs := make(chan error, numGoroutines*2)

	// Launch sender goroutines — each sends a unique payload.
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			payload := make([]byte, 64)
			// Fill with unique pattern so corruption is detectable.
			for j := range payload {
				payload[j] = byte(id)
			}
			client.SetPending(payload)
			datagrams := client.Tick()
			if len(datagrams) == 0 {
				errs <- nil // no datagram is fine if another goroutine won the race
				return
			}
			errs <- nil
		}(i)
	}

	// Launch receiver goroutines — each tries to receive datagrams.
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			// Generate a datagram from the client side to receive on server.
			payload := make([]byte, 32)
			for j := range payload {
				payload[j] = byte(id + 100)
			}
			client.SetPending(payload)
			datagrams := client.Tick()
			for _, dg := range datagrams {
				recvDiff(t, server, dg)
			}
			errs <- nil
		}(i)
	}

	// Collect all errors.
	for i := 0; i < numGoroutines*2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransportCapsNegotiation(t *testing.T) {
	server, client := newTestPair(t)

	server.SetCaps([]byte{CapSessionControl})
	client.SetCaps([]byte{CapSessionControl})

	// Exchange a message so caps are transmitted.
	server.SetPending([]byte("hello"))
	for _, dg := range server.Tick() {
		recvDiff(t, client, dg)
	}
	client.SetPending([]byte("world"))
	for _, dg := range client.Tick() {
		recvDiff(t, server, dg)
	}

	// Both should see remote caps now.
	if rc := client.RemoteCaps(); len(rc) == 0 {
		t.Fatal("client has no remote caps")
	}
	if rc := server.RemoteCaps(); len(rc) == 0 {
		t.Fatal("server has no remote caps")
	}

	// Both should agree on the capability.
	if !server.HasCap(CapSessionControl) {
		t.Fatal("server should have CapSessionControl")
	}
	if !client.HasCap(CapSessionControl) {
		t.Fatal("client should have CapSessionControl")
	}

	// Test intersection: server has bit 0x03, client has 0x01 → intersect = 0x01.
	server.SetCaps([]byte{0x03})
	client.SetCaps([]byte{0x01})

	server.SetPending([]byte("a"))
	for _, dg := range server.Tick() {
		recvDiff(t, client, dg)
	}
	client.SetPending([]byte("b"))
	for _, dg := range client.Tick() {
		recvDiff(t, server, dg)
	}

	if !server.HasCap(0x01) {
		t.Fatal("server should have bit 0x01")
	}
	if server.HasCap(0x02) {
		t.Fatal("server should not have bit 0x02 (client lacks it)")
	}
}

func TestTransportNoCaps(t *testing.T) {
	server, client := newTestPair(t)

	// No caps set — HasCap should return false.
	if server.HasCap(CapSessionControl) {
		t.Fatal("should be false with no caps")
	}
	if client.HasCap(CapSessionControl) {
		t.Fatal("should be false with no caps")
	}

	// Exchange without caps.
	server.SetPending([]byte("data"))
	for _, dg := range server.Tick() {
		recvDiff(t, client, dg)
	}

	// RemoteCaps should still be nil.
	if rc := client.RemoteCaps(); rc != nil {
		t.Fatalf("expected nil remote caps, got %x", rc)
	}
}

// TestTransportHighSequenceNumbers verifies that the transport works
// correctly when sequence numbers are very large (near 2^62).
func TestTransportHighSequenceNumbers(t *testing.T) {
	server, client := newTestPair(t)

	// Set server's outgoing sequence counter to near 2^62.
	server.mu.Lock()
	server.seqOut = (1 << 62) - 1
	server.mu.Unlock()

	server.SetPending([]byte("high seq test"))
	datagrams := server.Tick()
	if len(datagrams) == 0 {
		t.Fatal("no datagrams produced")
	}

	var diff []byte
	for _, dg := range datagrams {
		if d := recvDiff(t, client, dg); d != nil {
			diff = d
		}
	}
	if !bytes.Equal(diff, []byte("high seq test")) {
		t.Fatalf("diff = %q, want %q", diff, "high seq test")
	}
}
