package mosh

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// Transport implements the mosh State Synchronization Protocol (SSP).
//
// It manages sequence numbering, acknowledgements, retransmission timing,
// and the fragment/encrypt/decrypt pipeline. Both client and server use
// the same Transport with different direction bits.
//
// The caller provides state diffs (server: terminal output, client: keystrokes)
// and receives remote state updates.
type Transport struct {
	mu sync.Mutex

	ocb      *OCB
	toRemote uint64 // direction bit for outgoing (dirToServer or dirToClient)
	toLocal  uint64 // direction bit for incoming

	// Outgoing state (SSP §3).
	sentNum        uint64   // newest state we've sent (new_num)
	ackedByRemote  uint64   // newest state the remote has acknowledged
	sentStateNums  []uint64 // retained local states used to advertise throwaway_num
	pendingDiff    []byte   // diff payload waiting to be sent
	diffSent       bool     // true = pendingDiff has been sent at least once
	diffOldNum     uint64   // locked oldNum for all diffs until base advances
	hasPendingBase bool     // true = diffOldNum is locked
	pendingDataAck bool     // true = send ack ASAP (received data, not just ack)

	sendCacheValid     bool
	sendCacheFragments []Fragment

	// Incoming state — list of received state nums for old_num validation.
	receivedNums        []uint64 // ordered list of state nums we have
	ackNum              uint64   // latest received state num
	sentAckNum          uint64   // last ackNum we actually sent on wire
	throwawayNum        uint64   // oldest state we still hold
	lastRecvOldNum      uint64   // oldNum from most recently received diff
	lastRecvNewNum      uint64   // newNum from most recently received diff
	receiverQuenchUntil time.Time

	// Sequence counter for the crypto layer (independent of SSP state numbering).
	seqOut      uint64
	seqInMax    uint64
	seqInMaxSet bool // false until first datagram received

	// Timestamps.
	lastSend time.Time
	lastRecv time.Time
	lastTS   uint16 // last remote timestamp for echo

	// RTT estimation (Jacobson/Karels).
	srtt    time.Duration
	rttvar  time.Duration
	rto     time.Duration
	rttInit bool

	// Fragment assembler for incoming.
	assembler FragmentAssembler

	// Latch capability negotiation.
	localCaps  []byte
	remoteCaps []byte
}

// RecvResult reports whether a datagram passed the authenticated transport
// layer and, when available, the reassembled SSP diff payload.
type RecvResult struct {
	Diff          []byte
	Authenticated bool
}

const (
	initialRTO = 1000 * time.Millisecond
	minRTO     = 250 * time.Millisecond
	maxRTO     = 10 * time.Second

	moshProtocolVersion    = 2
	maxReceivedStates      = 1024
	receiverQuenchInterval = 15 * time.Second
)

// NewTransport creates a transport. isServer determines direction bits.
func NewTransport(ocb *OCB, isServer bool) *Transport {
	t := &Transport{
		ocb:           ocb,
		rto:           initialRTO,
		lastSend:      time.Now(),
		lastRecv:      time.Now(),
		receivedNums:  []uint64{0}, // start with state 0
		sentStateNums: []uint64{0}, // local states the peer may still reference
	}
	if isServer {
		t.toRemote = dirToClient
		t.toLocal = dirToServer
	} else {
		t.toRemote = dirToServer
		t.toLocal = dirToClient
	}
	return t
}

func (t *Transport) SetCaps(caps []byte) {
	t.mu.Lock()
	t.localCaps = append([]byte(nil), caps...)
	t.clearSendCacheLocked()
	t.mu.Unlock()
}

func (t *Transport) RemoteCaps() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteCaps
}

func (t *Transport) HasCap(bit byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.localCaps) == 0 || len(t.remoteCaps) == 0 {
		return false
	}
	idx := 0
	if idx >= len(t.localCaps) || idx >= len(t.remoteCaps) {
		return false
	}
	return (t.localCaps[idx] & t.remoteCaps[idx] & bit) != 0
}

// ForceNextSend forces the next tick to send, even with no pending diff.
func (t *Transport) ForceNextSend() {
	t.mu.Lock()
	t.lastSend = time.Time{} // zero time, always expired
	t.mu.Unlock()
}

// SetPending sets the diff payload to send on the next tick.
func (t *Transport) SetPending(diff []byte) {
	t.mu.Lock()
	if len(diff) > 0 {
		t.diffSent = false
		t.pendingDiff = append([]byte(nil), diff...)
	} else {
		t.pendingDiff = nil
		t.diffSent = false
		t.hasPendingBase = false
	}
	t.clearSendCacheLocked()
	t.mu.Unlock()
}

// Tick produces outgoing wire datagrams if it's time to send.
// Returns nil if nothing to send.
func (t *Transport) Tick() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Decide if we should send.
	haveDiff := len(t.pendingDiff) > 0
	haveNewDiff := haveDiff && !t.diffSent
	needAck := t.ackNum > t.sentAckNum
	sinceLastSend := now.Sub(t.lastSend)
	expired := sinceLastSend >= t.rto
	urgentAck := t.pendingDataAck

	shouldSend := haveNewDiff || needAck || expired || urgentAck
	if !shouldSend {
		return nil
	}

	// Build TransportInstruction.
	if haveNewDiff {
		t.sentNum++
		t.addSentStateLocked(t.sentNum)
		t.diffSent = true
		if !t.hasPendingBase {
			t.diffOldNum = t.ackedByRemote
			t.hasPendingBase = true
		}
	}
	t.pendingDataAck = false

	oldNum := t.ackedByRemote
	if haveDiff {
		oldNum = t.diffOldNum // use locked oldNum for diff retransmissions
	}

	ti := TransportInstruction{
		ProtocolVersion: moshProtocolVersion,
		OldNum:          oldNum,
		NewNum:          t.sentNum,
		AckNum:          t.ackNum,
		ThrowawayNum:    t.throwawayNumForSendLocked(),
		Diff:            t.pendingDiff,
		LatchCaps:       t.localCaps,
	}
	t.sentAckNum = t.ackNum
	// Do NOT nil pendingDiff — keep for retransmission until server acks.

	frags := t.fragmentsForSendLocked(ti, haveDiff)

	var datagrams [][]byte
	for i := range frags {
		wire := t.encryptFragment(&frags[i], now)
		datagrams = append(datagrams, wire)
	}

	t.lastSend = now
	return datagrams
}

// Recv processes an incoming wire datagram.
// It returns Authenticated only after direction, replay, OCB tag, and
// timestamp checks pass. Authenticated datagrams may still have no complete
// diff yet, for example heartbeats, duplicate fragments, or partial fragments.
func (t *Transport) Recv(wire []byte) (RecvResult, error) {
	if len(wire) < minDatagram {
		return RecvResult{}, nil
	}

	dirSeq := binary.BigEndian.Uint64(wire[:8])

	// Verify direction.
	if dirSeq&dirToClient != t.toLocal&dirToClient {
		return RecvResult{}, nil
	}

	seq := dirSeq & seqMask

	t.mu.Lock()
	if t.seqInMaxSet && seq <= t.seqInMax {
		t.mu.Unlock()
		return RecvResult{}, nil // replay
	}
	t.mu.Unlock()

	// Decrypt.
	var nonce [12]byte
	copy(nonce[4:], wire[:8])
	plaintext := t.ocb.Decrypt(nonce[:], wire[8:])
	if plaintext == nil {
		return RecvResult{}, nil
	}

	// Parse timestamp header (4 bytes).
	if len(plaintext) < 4 {
		return RecvResult{}, errors.New("mosh: authenticated datagram missing timestamp")
	}
	remoteTS := binary.BigEndian.Uint16(plaintext[0:])
	// plaintext[2:4] is timestamp_reply — used for RTT.
	tsReply := binary.BigEndian.Uint16(plaintext[2:])
	payload := plaintext[4:]

	// Update crypto sequence.
	t.mu.Lock()
	t.seqInMax = seq
	t.seqInMaxSet = true
	t.lastRecv = time.Now()
	t.lastTS = remoteTS
	t.mu.Unlock()

	// RTT estimation from timestamp echo.
	if tsReply != 0 {
		t.updateRTT(tsReply)
	}

	result := RecvResult{Authenticated: true}

	// Parse fragment.
	if len(payload) < fragmentHeaderSize {
		// Heartbeat with no fragment — that's fine.
		return result, nil
	}
	frag, err := UnmarshalFragment(payload)
	if err != nil {
		return RecvResult{}, err
	}

	// Reassemble.
	t.mu.Lock()
	msg, err := t.assembler.Add(frag)
	t.mu.Unlock()
	if err != nil {
		return RecvResult{}, err
	}
	if msg == nil {
		return result, nil
	}

	// Decompress → parse TransportInstruction.
	decompressed := zlibDecompress(msg)
	if decompressed == nil {
		return RecvResult{}, errors.New("mosh: authenticated datagram contains invalid compressed payload")
	}
	var ti TransportInstruction
	if err := ti.Unmarshal(decompressed); err != nil {
		return RecvResult{}, err
	}
	if ti.ProtocolVersion != moshProtocolVersion {
		return RecvResult{}, errors.New("mosh: protocol version mismatch")
	}

	if len(ti.LatchCaps) > 0 {
		t.mu.Lock()
		t.remoteCaps = ti.LatchCaps
		t.mu.Unlock()
	}

	// Process SSP fields (matching upstream mosh recv logic).
	t.mu.Lock()
	defer t.mu.Unlock()

	// Process ack from remote.
	if ti.AckNum > t.ackedByRemote {
		t.ackedByRemote = ti.AckNum
		t.processSentStateAckLocked(ti.AckNum)
		if t.ackedByRemote >= t.sentNum && t.pendingDiff != nil {
			t.pendingDiff = nil
			t.diffSent = false
			t.hasPendingBase = false
			t.clearSendCacheLocked()
		}
	}

	// Check if we already have new_num (dedup).
	for _, n := range t.receivedNums {
		if n == ti.NewNum {
			return result, nil
		}
	}

	// Check if we have old_num (required to apply diff).
	hasOld := false
	for _, n := range t.receivedNums {
		if n == ti.OldNum {
			hasOld = true
			break
		}
	}
	if !hasOld {
		return result, nil
	}

	// Process throwaway.
	if ti.ThrowawayNum > t.throwawayNum {
		t.throwawayNum = ti.ThrowawayNum
		filtered := t.receivedNums[:0]
		for _, n := range t.receivedNums {
			if n >= t.throwawayNum {
				filtered = append(filtered, n)
			}
		}
		t.receivedNums = filtered
	}

	if len(t.receivedNums) > maxReceivedStates {
		now := time.Now()
		if now.Before(t.receiverQuenchUntil) {
			return result, nil
		}
		t.receiverQuenchUntil = now.Add(receiverQuenchInterval)
	}

	// Track oldNum/newNum for state management.
	t.lastRecvOldNum = ti.OldNum
	t.lastRecvNewNum = ti.NewNum

	// Add new state.
	latest := t.addReceivedNumLocked(ti.NewNum)

	// Only acknowledge states that extend the latest received state.
	if latest {
		t.ackNum = ti.NewNum
		t.clearSendCacheLocked()
	}

	// Trigger immediate ack when we receive data.
	if len(ti.Diff) > 0 {
		t.pendingDataAck = true
	}

	result.Diff = ti.Diff
	return result, nil
}

func (t *Transport) clearSendCacheLocked() {
	t.sendCacheValid = false
	t.sendCacheFragments = nil
}

func (t *Transport) fragmentsForSendLocked(ti TransportInstruction, cacheable bool) []Fragment {
	if cacheable && t.sendCacheValid {
		return t.sendCacheFragments
	}

	pbData := ti.Marshal()
	compressed := zlibCompress(pbData)
	frags := Fragmentize(ti.NewNum, compressed)
	if cacheable {
		t.sendCacheFragments = frags
		t.sendCacheValid = true
	}
	return frags
}

func (t *Transport) addSentStateLocked(num uint64) {
	if len(t.sentStateNums) > 0 && t.sentStateNums[len(t.sentStateNums)-1] == num {
		return
	}
	t.sentStateNums = append(t.sentStateNums, num)
	if len(t.sentStateNums) > 32 {
		i := len(t.sentStateNums) - 16
		// Match C mosh: keep the oldest state for throwaway_num safety and
		// the newest states for likely ACKs, then cull one state in the middle.
		t.sentStateNums = append(t.sentStateNums[:i], t.sentStateNums[i+1:]...)
	}
}

func (t *Transport) addReceivedNumLocked(num uint64) bool {
	for i, n := range t.receivedNums {
		if n > num {
			t.receivedNums = append(t.receivedNums, 0)
			copy(t.receivedNums[i+1:], t.receivedNums[i:])
			t.receivedNums[i] = num
			return false
		}
	}
	t.receivedNums = append(t.receivedNums, num)
	return true
}

func (t *Transport) processSentStateAckLocked(ack uint64) {
	found := false
	for _, n := range t.sentStateNums {
		if n == ack {
			found = true
			break
		}
	}
	if !found {
		return
	}
	kept := t.sentStateNums[:0]
	for _, n := range t.sentStateNums {
		if n >= ack {
			kept = append(kept, n)
		}
	}
	if len(kept) == 0 {
		kept = append(kept, ack)
	}
	t.sentStateNums = kept
	t.clearSendCacheLocked()
}

func (t *Transport) throwawayNumForSendLocked() uint64 {
	var throwaway uint64
	if len(t.sentStateNums) > 0 {
		throwaway = t.sentStateNums[0]
	}
	if t.hasPendingBase && t.diffOldNum < throwaway {
		throwaway = t.diffOldNum
	}
	return throwaway
}

// AckedByRemote returns the highest state number the remote has acked.
func (t *Transport) AckedByRemote() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ackedByRemote
}

// SentNum returns the current sent state number.
func (t *Transport) SentNum() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sentNum
}

// LastRecvOldNum returns the oldNum from the most recently received diff.
func (t *Transport) LastRecvOldNum() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastRecvOldNum
}

// LastRecvNewNum returns the newNum from the most recently received diff.
func (t *Transport) LastRecvNewNum() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastRecvNewNum
}

// ThrowawayNum returns the server's throwaway number — states below this
// are no longer referenced by the server and can be safely pruned.
func (t *Transport) ThrowawayNum() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.throwawayNum
}

// LastRecv returns the time of the last received datagram.
func (t *Transport) LastRecv() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastRecv
}

// RTO returns the current retransmission timeout.
func (t *Transport) RTO() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rto
}

// encryptFragment encrypts a fragment and wraps it in the mosh wire format.
// Caller holds t.mu.
func (t *Transport) encryptFragment(f *Fragment, now time.Time) []byte {
	t.seqOut++
	seq := t.seqOut

	dirSeq := t.toRemote | (seq & seqMask)
	var dirSeqBytes [8]byte
	binary.BigEndian.PutUint64(dirSeqBytes[:], dirSeq)

	var nonce [12]byte
	copy(nonce[4:], dirSeqBytes[:])

	// Plaintext: [timestamp:2][timestamp_reply:2][fragment]
	fragWire := f.Marshal()
	ts := uint16(now.UnixMilli() & 0xffff)
	plaintext := make([]byte, 4+len(fragWire))
	binary.BigEndian.PutUint16(plaintext[0:], ts)
	binary.BigEndian.PutUint16(plaintext[2:], t.lastTS)
	copy(plaintext[4:], fragWire)

	tagAndCT := t.ocb.Encrypt(nonce[:], plaintext)

	wire := make([]byte, 8+len(tagAndCT))
	copy(wire[:8], dirSeqBytes[:])
	copy(wire[8:], tagAndCT)
	return wire
}

// updateRTT updates the RTT estimate from a timestamp echo.
func (t *Transport) updateRTT(tsReply uint16) {
	now16 := uint16(time.Now().UnixMilli() & 0xffff)
	// Compute RTT in milliseconds, handling 16-bit wraparound.
	rttMS := int(now16) - int(tsReply)
	if rttMS < 0 {
		rttMS += 65536
	}
	if rttMS > 30000 {
		return // implausible
	}
	rtt := time.Duration(rttMS) * time.Millisecond

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.rttInit {
		t.srtt = rtt
		t.rttvar = rtt / 2
		t.rttInit = true
	} else {
		// RFC 6298 Jacobson/Karels.
		delta := t.srtt - rtt
		if delta < 0 {
			delta = -delta
		}
		t.rttvar = (3*t.rttvar + delta) / 4
		t.srtt = (7*t.srtt + rtt) / 8
	}

	t.rto = t.srtt + 4*t.rttvar
	if t.rto < minRTO {
		t.rto = minRTO
	}
	if t.rto > maxRTO {
		t.rto = maxRTO
	}
}

var zlibWriterPool = sync.Pool{
	New: func() any {
		return zlib.NewWriter(io.Discard)
	},
}

// zlibCompress compresses data with zlib (default level).
func zlibCompress(data []byte) []byte {
	var buf bytes.Buffer
	w := zlibWriterPool.Get().(*zlib.Writer)
	w.Reset(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	zlibWriterPool.Put(w)
	return buf.Bytes()
}

// zlibDecompress decompresses zlib data. Returns nil on error.
// Limits output to 1 MiB to prevent decompression bombs.
func zlibDecompress(data []byte) []byte {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	const maxDecompressedSize = 1 << 20
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize+1))
	if err != nil {
		r.Close()
		return nil
	}
	if len(out) > maxDecompressedSize {
		r.Close()
		return nil
	}
	if err := r.Close(); err != nil {
		return nil
	}
	return out
}
