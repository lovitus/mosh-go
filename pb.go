package mosh

import (
	"encoding/binary"
	"errors"
)

// Hand-rolled protobuf encoding for the three mosh .proto schemas.
// Field numbers match upstream mobile-shell/mosh exactly.

// TransportInstruction is the outer transport wrapper (TransportBuffers.Instruction).
//
// Field numbers:
//
//	1: protocol_version (uint32)
//	2: old_num          (uint64)
//	3: new_num          (uint64)
//	4: ack_num          (uint64)
//	5: throwaway_num    (uint64)
//	6: diff             (bytes)
//	7: chaff            (bytes)
type TransportInstruction struct {
	ProtocolVersion uint32
	OldNum          uint64
	NewNum          uint64
	AckNum          uint64
	ThrowawayNum    uint64
	Diff            []byte
	Chaff           []byte
	LatchCaps       []byte
}

// LatchControl is a latch extension control message.
type LatchControl struct {
	Type    uint32
	Payload []byte
}

const (
	CtrlSessionListReq  uint32 = 1
	CtrlSessionListResp uint32 = 2
	CtrlSessionSwitch   uint32 = 3
	CtrlSessionSwitched uint32 = 4
	CtrlSessionCreate   uint32 = 5
	CtrlSessionCreated  uint32 = 6
)

const (
	CapSessionControl byte = 1 << 0
)

// HostInstruction is one instruction within a HostMessage.
// Represents the extension fields of HostBuffers.Instruction:
//
//	field 2 → HostBytes { field 4: hoststring }
//	field 3 → ResizeMessage { field 5: width, field 6: height }
//	field 7 → EchoAck { field 8: echo_ack_num }
type HostInstruction struct {
	Hoststring []byte
	Width      int32 // 0 = not present
	Height     int32 // 0 = not present
	EchoAckNum int64 // -1 = not present
	Control    *LatchControl
}

// UserInstruction is one instruction within a UserMessage.
// Represents the extension fields of ClientBuffers.Instruction:
//
//	field 2 → Keystroke { field 4: keys }
//	field 3 → ResizeMessage { field 5: width, field 6: height }
type UserInstruction struct {
	Keys    []byte
	Width   int32 // 0 = not present
	Height  int32 // 0 = not present
	Control *LatchControl
}

// Wire type constants.
const (
	wireVarint = 0
	wireBytes  = 2
)

var errTruncated = errors.New("mosh/pb: truncated message")

// --- Encoding helpers ---

func appendTag(b []byte, field int, wtype int) []byte {
	return appendVarint(b, uint64(field<<3|wtype))
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendTagVarint(b []byte, field int, v uint64) []byte {
	b = appendTag(b, field, wireVarint)
	return appendVarint(b, v)
}

func appendTagBytes(b []byte, field int, data []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// --- Decoding helpers ---

func decodeVarint(b []byte) (uint64, int) {
	var v uint64
	for i, c := range b {
		if i >= binary.MaxVarintLen64 {
			return 0, 0
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

func decodeTag(b []byte) (field, wtype int, n int) {
	v, n := decodeVarint(b)
	if n == 0 {
		return 0, 0, 0
	}
	return int(v >> 3), int(v & 7), n
}

// skipField advances past an unknown field.
func skipField(b []byte, wtype int) int {
	switch wtype {
	case wireVarint:
		_, n := decodeVarint(b)
		return n
	case wireBytes:
		length, n := decodeVarint(b)
		if n == 0 || length > uint64(len(b)-n) {
			return 0
		}
		return n + int(length)
	case 5: // 32-bit
		if len(b) < 4 {
			return 0
		}
		return 4
	case 1: // 64-bit
		if len(b) < 8 {
			return 0
		}
		return 8
	}
	return 0
}

func consumeVarint(b []byte) (uint64, []byte, bool) {
	v, n := decodeVarint(b)
	if n == 0 {
		return 0, nil, false
	}
	return v, b[n:], true
}

func consumeBytes(b []byte) ([]byte, []byte, bool) {
	length, n := decodeVarint(b)
	if n == 0 || length > uint64(len(b)-n) {
		return nil, nil, false
	}
	end := n + int(length)
	return b[n:end], b[end:], true
}

// --- TransportInstruction ---

func (ti *TransportInstruction) Marshal() []byte {
	var b []byte
	if ti.ProtocolVersion != 0 {
		b = appendTagVarint(b, 1, uint64(ti.ProtocolVersion))
	}
	b = appendTagVarint(b, 2, ti.OldNum)
	b = appendTagVarint(b, 3, ti.NewNum)
	b = appendTagVarint(b, 4, ti.AckNum)
	b = appendTagVarint(b, 5, ti.ThrowawayNum)
	if len(ti.Diff) > 0 {
		b = appendTagBytes(b, 6, ti.Diff)
	}
	if len(ti.Chaff) > 0 {
		b = appendTagBytes(b, 7, ti.Chaff)
	}
	if len(ti.LatchCaps) > 0 {
		b = appendTagBytes(b, 8, ti.LatchCaps)
	}
	return b
}

func (ti *TransportInstruction) Unmarshal(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]

		switch field {
		case 1:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			ti.ProtocolVersion = uint32(v)
			data = rest
		case 2:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			ti.OldNum = v
			data = rest
		case 3:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			ti.NewNum = v
			data = rest
		case 4:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			ti.AckNum = v
			data = rest
		case 5:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			ti.ThrowawayNum = v
			data = rest
		case 6:
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			ti.Diff = append([]byte(nil), value...)
			data = rest
		case 7:
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			ti.Chaff = append([]byte(nil), value...)
			data = rest
		case 8:
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			ti.LatchCaps = append([]byte(nil), value...)
			data = rest
		default:
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

// --- HostMessage ---

// MarshalHostMessage encodes a list of HostInstructions as a HostMessage protobuf.
func MarshalHostMessage(instrs []HostInstruction) []byte {
	return marshalHostMessage(instrs)
}

func marshalHostMessage(instrs []HostInstruction) []byte {
	var b []byte
	for i := range instrs {
		sub := instrs[i].marshal()
		b = appendTagBytes(b, 1, sub)
	}
	return b
}

// UnmarshalHostMessage decodes a HostMessage protobuf into a list of HostInstructions.
func UnmarshalHostMessage(data []byte) ([]HostInstruction, error) {
	return unmarshalHostMessage(data)
}

func unmarshalHostMessage(data []byte) ([]HostInstruction, error) {
	var instrs []HostInstruction
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return nil, errTruncated
		}
		data = data[n:]
		if field != 1 {
			skip := skipField(data, wtype)
			if skip == 0 {
				return nil, errTruncated
			}
			data = data[skip:]
			continue
		}
		if wtype != wireBytes {
			return nil, errTruncated
		}
		value, rest, ok := consumeBytes(data)
		if !ok {
			return nil, errTruncated
		}
		var hi HostInstruction
		hi.EchoAckNum = -1
		if err := hi.unmarshal(value); err != nil {
			return nil, err
		}
		instrs = append(instrs, hi)
		data = rest
	}
	return instrs, nil
}

func (hi *HostInstruction) marshal() []byte {
	var b []byte
	if len(hi.Hoststring) > 0 {
		// field 2: HostBytes submessage containing field 4: hoststring
		sub := appendTagBytes(nil, 4, hi.Hoststring)
		b = appendTagBytes(b, 2, sub)
	}
	if hi.Width > 0 || hi.Height > 0 {
		// field 3: ResizeMessage submessage containing field 5: width, field 6: height
		sub := appendTagVarint(nil, 5, uint64(hi.Width))
		sub = appendTagVarint(sub, 6, uint64(hi.Height))
		b = appendTagBytes(b, 3, sub)
	}
	if hi.EchoAckNum >= 0 {
		// field 7: EchoAck submessage containing field 8: echo_ack_num
		sub := appendTagVarint(nil, 8, uint64(hi.EchoAckNum))
		b = appendTagBytes(b, 7, sub)
	}
	if hi.Control != nil {
		sub := appendTagVarint(nil, 10, uint64(hi.Control.Type))
		if len(hi.Control.Payload) > 0 {
			sub = appendTagBytes(sub, 11, hi.Control.Payload)
		}
		b = appendTagBytes(b, 9, sub)
	}
	return b
}

func (hi *HostInstruction) unmarshal(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]

		switch field {
		case 2: // HostBytes
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			if err := hi.unmarshalHostBytes(value); err != nil {
				return err
			}
			data = rest
		case 3: // ResizeMessage
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			if err := hi.unmarshalResize(value); err != nil {
				return err
			}
			data = rest
		case 7: // EchoAck
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			if err := hi.unmarshalEchoAck(value); err != nil {
				return err
			}
			data = rest
		case 9: // LatchControl
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			ctrl := &LatchControl{}
			if err := ctrl.unmarshal(value); err != nil {
				return err
			}
			hi.Control = ctrl
			data = rest
		default:
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

func (hi *HostInstruction) unmarshalHostBytes(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]
		if field == 4 {
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			hi.Hoststring = append([]byte(nil), value...)
			data = rest
		} else {
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

func (hi *HostInstruction) unmarshalResize(data []byte) error {
	return unmarshalResize(data, &hi.Width, &hi.Height)
}

func (hi *HostInstruction) unmarshalEchoAck(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]
		if field == 8 {
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			hi.EchoAckNum = int64(v)
			data = rest
		} else {
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

// --- UserMessage ---

// MarshalUserMessage encodes a list of UserInstructions as a UserMessage protobuf.
func MarshalUserMessage(instrs []UserInstruction) []byte {
	return marshalUserMessage(instrs)
}

func marshalUserMessage(instrs []UserInstruction) []byte {
	var b []byte
	for i := range instrs {
		sub := instrs[i].marshal()
		b = appendTagBytes(b, 1, sub)
	}
	return b
}

func unmarshalUserMessage(data []byte) ([]UserInstruction, error) {
	var instrs []UserInstruction
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return nil, errTruncated
		}
		data = data[n:]
		if field != 1 {
			skip := skipField(data, wtype)
			if skip == 0 {
				return nil, errTruncated
			}
			data = data[skip:]
			continue
		}
		if wtype != wireBytes {
			return nil, errTruncated
		}
		value, rest, ok := consumeBytes(data)
		if !ok {
			return nil, errTruncated
		}
		var ui UserInstruction
		if err := ui.unmarshal(value); err != nil {
			return nil, err
		}
		instrs = append(instrs, ui)
		data = rest
	}
	return instrs, nil
}

func (ui *UserInstruction) marshal() []byte {
	var b []byte
	if len(ui.Keys) > 0 {
		// field 2: Keystroke submessage containing field 4: keys
		sub := appendTagBytes(nil, 4, ui.Keys)
		b = appendTagBytes(b, 2, sub)
	}
	if ui.Width > 0 || ui.Height > 0 {
		// field 3: ResizeMessage submessage
		sub := appendTagVarint(nil, 5, uint64(ui.Width))
		sub = appendTagVarint(sub, 6, uint64(ui.Height))
		b = appendTagBytes(b, 3, sub)
	}
	if ui.Control != nil {
		sub := appendTagVarint(nil, 10, uint64(ui.Control.Type))
		if len(ui.Control.Payload) > 0 {
			sub = appendTagBytes(sub, 11, ui.Control.Payload)
		}
		b = appendTagBytes(b, 9, sub)
	}
	return b
}

func (ui *UserInstruction) unmarshal(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]

		switch field {
		case 2: // Keystroke
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			if err := ui.unmarshalKeystroke(value); err != nil {
				return err
			}
			data = rest
		case 3: // ResizeMessage
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			if err := unmarshalResize(value, &ui.Width, &ui.Height); err != nil {
				return err
			}
			data = rest
		case 9: // LatchControl
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			ctrl := &LatchControl{}
			if err := ctrl.unmarshal(value); err != nil {
				return err
			}
			ui.Control = ctrl
			data = rest
		default:
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

func (ui *UserInstruction) unmarshalKeystroke(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]
		if field == 4 {
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			ui.Keys = append(ui.Keys, value...)
			data = rest
		} else {
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

// Shared ResizeMessage decoder (used by both Host and User).
func unmarshalResize(data []byte, width, height *int32) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]
		switch field {
		case 5:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			*width = int32(v)
			data = rest
		case 6:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			*height = int32(v)
			data = rest
		default:
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}

func (c *LatchControl) unmarshal(data []byte) error {
	for len(data) > 0 {
		field, wtype, n := decodeTag(data)
		if n == 0 {
			return errTruncated
		}
		data = data[n:]
		switch field {
		case 10:
			if wtype != wireVarint {
				return errTruncated
			}
			v, rest, ok := consumeVarint(data)
			if !ok {
				return errTruncated
			}
			c.Type = uint32(v)
			data = rest
		case 11:
			if wtype != wireBytes {
				return errTruncated
			}
			value, rest, ok := consumeBytes(data)
			if !ok {
				return errTruncated
			}
			c.Payload = append([]byte(nil), value...)
			data = rest
		default:
			skip := skipField(data, wtype)
			if skip == 0 {
				return errTruncated
			}
			data = data[skip:]
		}
	}
	return nil
}
