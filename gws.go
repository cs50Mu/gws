package gws

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"strings"
	"unicode/utf8"
)

var (
	ErrBadClientHandshake     = errors.New("bad client handshake")
	ErrUnknownOpcode          = errors.New("unknown opcode")
	ErrConnClosed             = errors.New("conn is closed")
	ErrCloseMsgRecved         = errors.New("Close msg is recved from the peer")
	ErrExtensionNotNegotiated = errors.New("rsv1,rsv2,rsv3 MUST be 0 unless an extension is negotiated")
	ErrControlFrameTooBig     = errors.New("Control frame is too big")
	ErrBadFrameRecvd          = errors.New("recved bad frame from the peer")
	ErrInvalidUtf8Recvd       = errors.New("invalid utf8 byte stream recvd")
	ErrShortUtf8              = errors.New("short utf8 byte stream recvd, send more")
)

const (
	// the max chunk size when writing a frame
	// msg with a bigger size will be splitted
	// todo: make chunkSize customizable
	msgMaxChunkSize = 4096
	finalBit        = 1 << 7
	rsv1Bit         = 1 << 6
	rsv2Bit         = 1 << 5
	rsv3Bit         = 1 << 4
	maskBit         = 1 << 7
)

type WS struct {
	conn     net.Conn
	bufw     *bufio.Writer
	bufr     *bufio.Reader
	isClosed bool
	isClient bool
	opcode   Opcode
}

func newWS(conn net.Conn, isClient bool) *WS {
	return &WS{
		conn:     conn,
		bufw:     bufio.NewWriter(conn),
		bufr:     bufio.NewReader(conn),
		isClient: isClient,
	}
}

func NewClientWS(conn net.Conn) *WS {
	return newWS(conn, true)
}

func NewServerWS(conn net.Conn) *WS {
	return newWS(conn, false)
}

func (ws *WS) ServerHandshake() error {
	statusLine, err := ws.bufr.ReadString('\n')
	if err != nil {
		return err
	}
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		log.Printf("statusLine: %v\n", statusLine)
		return errors.New("bad status line")
	}
	log.Printf("method: %v, uri: %v, proto: %v\n", parts[0], parts[1], parts[2])
	// headers
	var headerLine string
	var secWebsocketKey string
	for {
		headerLine, err = ws.bufr.ReadString('\n')
		if err != nil {
			return err
		}
		if len(headerLine) == 2 && headerLine[0] == '\r' && headerLine[1] == '\n' {
			break
		}
		parts := strings.SplitN(headerLine, ":", 2)
		if len(parts) < 2 {
			log.Printf("headerLine: %v\n", headerLine)
			return errors.New("bad resp header")
		}
		headerName := parts[0]
		headerValue := strings.TrimSpace(parts[1])
		log.Printf("%v: %v\n", headerName, headerValue)
		if headerName == "Sec-WebSocket-Key" {
			decoded, err := base64.StdEncoding.DecodeString(headerValue)
			if err != nil {
				return err
			}
			if len(decoded) != 16 {
				return ErrBadClientHandshake
			}
			secWebsocketKey = headerValue
		}
	}

	// send server resp
	ws.bufw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	ws.bufw.WriteString("Upgrade: websocket\r\n")
	ws.bufw.WriteString("Connection: Upgrade\r\n")
	ws.bufw.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %v\r\n", genSecWebsocketAccept(secWebsocketKey)))
	ws.bufw.WriteString("\r\n")
	return ws.bufw.Flush()
}

func genSecWebsocketAccept(key string) string {
	concated := fmt.Sprintf("%v258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key)
	sha1Sum := sha1.Sum([]byte(concated))
	return base64.StdEncoding.EncodeToString(sha1Sum[:])
}

// GET /chat HTTP/1.1
// Host: example.com:8000
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
// Sec-WebSocket-Version: 13
func (ws *WS) ClientHandshake(host string) error {
	var err error
	ws.bufw.WriteString("GET /chat HTTP/1.1\r\n")
	ws.bufw.WriteString(fmt.Sprintf("Host: %v\r\n", host))
	ws.bufw.WriteString("Upgrade: websocket\r\n")
	ws.bufw.WriteString("Connection: Upgrade\r\n")
	ws.bufw.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	ws.bufw.WriteString("Sec-WebSocket-Version: 13\r\n")
	ws.bufw.WriteString("\r\n")
	if err = ws.bufw.Flush(); err != nil {
		return err
	}

	// read resp from server
	// HTTP/1.1 101 Switching Protocols
	// Upgrade: websocket
	// Connection: Upgrade
	// Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
	statusLine, err := ws.bufr.ReadString('\n')
	if err != nil {
		return err
	}
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		log.Printf("statusLine: %v\n", statusLine)
		return errors.New("bad status line")
	}
	log.Printf("proto: %v, status: %v, msg: %v\n", parts[0], parts[1], parts[2])
	// headers
	var headerLine string
	for {
		headerLine, err = ws.bufr.ReadString('\n')
		if err != nil {
			return err
		}
		if len(headerLine) == 2 && headerLine[0] == '\r' && headerLine[1] == '\n' {
			break
		}
		parts := strings.SplitN(headerLine, ":", 2)
		if len(parts) < 2 {
			log.Printf("headerLine: %v\n", headerLine)
			return errors.New("bad resp header")
		}
		headerName := parts[0]
		headerValue := strings.TrimSpace(parts[1])
		log.Printf("%v: %v\n", headerName, headerValue)
		if headerName == "sec-websocket-accept" {
			if headerValue != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
				return ErrBadClientHandshake
			}
		}
	}

	return nil
}

type Opcode byte

const (
	OpcodeCont  Opcode = 0x0
	OpcodeText  Opcode = 0x1
	OpcodeBin   Opcode = 0x2
	OpcodeClose Opcode = 0x8
	OpcodePing  Opcode = 0x9
	OpcodePong  Opcode = 0xA
)

// RFC 6455 - Section 5.5:
// Control frames are identified by opcodes where the most significant
// bit of the opcode is 1.
func (oc Opcode) isControl() bool {
	return byte(oc)&0x8 != 0
}

func (oc Opcode) String() string {
	switch oc {
	case OpcodeCont:
		return "Cont"
	case OpcodeText:
		return "Text"
	case OpcodeBin:
		return "Binary"
	case OpcodeClose:
		return "Close"
	case OpcodePing:
		return "Ping"
	case OpcodePong:
		return "Pong"
	default:
		panic(ErrUnknownOpcode)
	}
}

func (ws *WS) WriteFrame(payload []byte, opcode Opcode, isFin, needMask bool) error {
	var buf bytes.Buffer
	b0 := byte(opcode)
	if isFin {
		b0 |= finalBit
	}
	buf.WriteByte(b0)
	// mask and payloadLen
	b1 := byte(0)
	if needMask {
		b1 |= maskBit
	}
	payloadLen := len(payload)
	if payloadLen <= 125 {
		b1 |= byte(payloadLen)
		buf.WriteByte(b1)
	} else if payloadLen <= math.MaxUint16 {
		buf.WriteByte(b1 | 126)
		// 2 more bytes
		dataLen := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLen, uint16(payloadLen))
		buf.Write(dataLen)
	} else {
		buf.WriteByte(b1 | 127)
		// 4 more bytes
		dataLen := make([]byte, 8)
		binary.BigEndian.PutUint32(dataLen, uint32(payloadLen))
		buf.Write(dataLen)
	}
	// masking key
	var mask []byte
	if needMask {
		mask = make([]byte, 4)
		for i := 0; i < 4; i++ {
			mask[i] = byte(rand.Int())
		}
		buf.Write(mask)
	}
	// payload
	if needMask {
		payload = maskUnmask(payload, mask)
	}
	buf.Write(payload)

	ws.bufw.Write(buf.Bytes())
	return ws.bufw.Flush()
}

func maskUnmask(payload, mask []byte) []byte {
	res := make([]byte, len(payload))
	for i := 0; i < len(payload); i++ {
		res[i] = payload[i] ^ mask[i%4]
	}

	return res
}

type Frame struct {
	Opcode  Opcode
	Fin     bool
	Rsv1    bool
	Rsv2    bool
	Rsv3    bool
	Masked  bool
	Payload []byte
}

func (ws *WS) ReadFrame() (*Frame, error) {
	data := make([]byte, 2)
	_, err := io.ReadFull(ws.bufr, data)
	if err != nil {
		return nil, err
	}

	frame := &Frame{
		Opcode: Opcode(data[0] & 0xf),
		Fin:    data[0]&finalBit != 0,
		Rsv1:   data[0]&rsv1Bit != 0,
		Rsv2:   data[0]&rsv2Bit != 0,
		Rsv3:   data[0]&rsv3Bit != 0,
		Masked: data[1]&maskBit != 0,
	}
	// RFC 6455 - Section 5.2:
	// >  RSV1, RSV2, RSV3:  1 bit each
	// >
	// >     MUST be 0 unless an extension is negotiated that defines meanings
	// >     for non-zero values.  If a nonzero value is received and none of
	// >     the negotiated extensions defines the meaning of such a nonzero
	// >     value, the receiving endpoint MUST _Fail the WebSocket
	// >     Connection_.
	if frame.Rsv1 || frame.Rsv2 || frame.Rsv3 {
		_ = ws.WriteFrame(frame.Payload, OpcodeClose, true, false)
		return nil, ErrExtensionNotNegotiated
	}

	payloadLen := data[1] & 0x7f
	// RFC 6455 - Section 5.5: Control Frames
	//   All control frames MUST have a payload length of 125 bytes or less
	//   and MUST NOT be fragmented.
	if frame.Opcode.isControl() && (payloadLen > 125 || !frame.Fin) {
		_ = ws.WriteFrame(frame.Payload, OpcodeClose, true, false)
		return nil, ErrControlFrameTooBig
	}

	var realPayloadlen uint64
	if payloadLen < 126 {
		realPayloadlen = uint64(payloadLen)
	} else if payloadLen == 126 {
		// 2 bytes
		data := make([]byte, 2)
		if _, err := io.ReadFull(ws.bufr, data); err != nil {
			return nil, err
		}
		realPayloadlen = uint64(binary.BigEndian.Uint16(data))
	} else { // 127
		// 8 bytes
		data := make([]byte, 8)
		if _, err := io.ReadFull(ws.bufr, data); err != nil {
			return nil, err
		}
		realPayloadlen = binary.BigEndian.Uint64(data)
	}

	var mask []byte
	// masking
	if frame.Masked { // 4 bytes
		mask = make([]byte, 4)
		_, err := io.ReadFull(ws.bufr, mask)
		if err != nil {
			return nil, err
		}
	}
	log.Printf("recved payloadLen: %v\n", realPayloadlen)
	// payload
	if realPayloadlen > 0 {
		payload := make([]byte, realPayloadlen)
		_, err = io.ReadFull(ws.bufr, payload)
		if err != nil {
			return nil, err
		}
		// log.Printf("payload: %+v\n", payload)
		if frame.Masked {
			payload = maskUnmask(payload, mask)
		}
		frame.Payload = payload
	}

	return frame, nil
}

// Close codes defined in RFC 6455, section 11.7.
const (
	CloseNormalClosure           = 1000
	CloseGoingAway               = 1001
	CloseProtocolError           = 1002
	CloseUnsupportedData         = 1003
	CloseNoStatusReceived        = 1005
	CloseAbnormalClosure         = 1006
	CloseInvalidFramePayloadData = 1007
	ClosePolicyViolation         = 1008
	CloseMessageTooBig           = 1009
	CloseMandatoryExtension      = 1010
	CloseInternalServerErr       = 1011
	CloseServiceRestart          = 1012
	CloseTryAgainLater           = 1013
	CloseTLSHandshake            = 1015
)

var validReceivedCloseCodes = map[int]bool{
	// see http://www.iana.org/assignments/websocket/websocket.xhtml#close-code-number

	CloseNormalClosure:           true,
	CloseGoingAway:               true,
	CloseProtocolError:           true,
	CloseUnsupportedData:         true,
	CloseNoStatusReceived:        false,
	CloseAbnormalClosure:         false,
	CloseInvalidFramePayloadData: true,
	ClosePolicyViolation:         true,
	CloseMessageTooBig:           true,
	CloseMandatoryExtension:      true,
	CloseInternalServerErr:       true,
	CloseServiceRestart:          true,
	CloseTryAgainLater:           true,
	CloseTLSHandshake:            false,
}

func isValidReceivedCloseCode(code int) bool {
	return validReceivedCloseCodes[code] || (code >= 3000 && code <= 4999)
}

func parseCloseFrameBody(data []byte) (statusCode uint16, reason string, err error) {
	if len(data) < 2 {
		err = ErrBadFrameRecvd
		return
	}
	statusCode = binary.BigEndian.Uint16(data[:2])
	if !utf8.Valid(data[2:]) {
		err = ErrInvalidUtf8Recvd
		return
	}
	return statusCode, string(data[2:]), nil
}

// ReadMsg read msg from the websocket
// only Text or Bin msg are returned for caller to handle
// other msgs: Ping/Pong are handled automaticly, Close msg are
// returned as error
func (ws *WS) ReadMsg() (msgType Opcode, payload []byte, err error) {
	var frame *Frame
	var buf bytes.Buffer
	for {
		frame, err = ws.ReadFrame()
		if err != nil {
			return
		}
		switch frame.Opcode {
		case OpcodePing:
			log.Println("got ping msg")
			if err = ws.WriteFrame(frame.Payload, OpcodePong, true, false); err != nil {
				return
			}
		case OpcodePong:
			// ignore
			continue
		case OpcodeClose:
			log.Println("got close msg")
			if len(frame.Payload) > 0 {
				statusCode, reason, err := parseCloseFrameBody(frame.Payload)
				if err != nil {
					// fail the conn
					_ = ws.WriteFrame(nil, OpcodeClose, true, false)
					return 0, nil, err
				}
				log.Printf("statusCode: %v, reason: %s\n", statusCode, reason)
				if !isValidReceivedCloseCode(int(statusCode)) {
					// fail the conn
					_ = ws.WriteFrame(nil, OpcodeClose, true, false)
					return 0, nil, err
				}
			}
			_ = ws.WriteFrame(frame.Payload, OpcodeClose, true, false)
			ws.isClosed = true
			// close the underlying conn
			// ws.conn.Close()
			err = ErrCloseMsgRecved
			return
		case OpcodeCont:
			// fragmented msg not started with a
			// frame whose opcode is other than 0
			if msgType == OpcodeCont {
				_ = ws.WriteFrame(nil, OpcodeClose, true, false)
				err = ErrBadFrameRecvd
				return
			}
			buf.Write(frame.Payload)
			if msgType == OpcodeText {
				framePayload := buf.Bytes()
				for len(framePayload) > 0 {
					_, size, parseErr := utf8ToRune(framePayload)
					if parseErr != nil {
						if parseErr == ErrShortUtf8 {
							break
						} else {
							err = ErrInvalidUtf8Recvd
							return
						}
					}
					framePayload = framePayload[size:]
				}
			}
			// log.Println("got cont msg")
			if frame.Fin {
				// // RFC 6455 - Section 8.1: Handling Errors in UTF-8-Encoded Data
				// //   When an endpoint is to interpret a byte stream as UTF-8 but finds
				// //   that the byte stream is not, in fact, a valid UTF-8 stream, that
				// //   endpoint MUST _Fail the WebSocket Connection_.
				// if msgType == OpcodeText && !utf8.Valid(buf.Bytes()) {
				// 	_ = ws.WriteFrame(nil, OpcodeClose, true, false)
				// 	err = ErrInvalidUtf8Recvd
				// 	return
				// }
				// log.Printf("got fragmented msg: %v", buf.String())
				payload = make([]byte, buf.Len())
				copy(payload, buf.Bytes()) // need deep copy
				buf.Reset()
				return
			}
		case OpcodeBin, OpcodeText:
			// all data frames after the initial data frame must have
			// opcode 0.
			if msgType != OpcodeCont {
				_ = ws.WriteFrame(nil, OpcodeClose, true, false)
				err = ErrBadFrameRecvd
				return
			}
			msgType = frame.Opcode
			if frame.Fin {
				// RFC 6455 - Section 8.1: Handling Errors in UTF-8-Encoded Data
				//   When an endpoint is to interpret a byte stream as UTF-8 but finds
				//   that the byte stream is not, in fact, a valid UTF-8 stream, that
				//   endpoint MUST _Fail the WebSocket Connection_.
				if msgType == OpcodeText && !utf8.Valid(frame.Payload) {
					_ = ws.WriteFrame(nil, OpcodeClose, true, false)
					err = ErrInvalidUtf8Recvd
					return
				}
				payload = make([]byte, len(frame.Payload))
				copy(payload, frame.Payload) // need deep copy
				buf.Reset()
				return
			} else {
				buf.Write(frame.Payload)
			}
		default:
			_ = ws.WriteFrame(nil, OpcodeClose, true, false)
			err = ErrUnknownOpcode
			return
		}
	}
}

type Msg struct {
	Opcode  Opcode
	Payload []byte
}

type MsgHandler func(msg *Msg, ws *WS) error

func (ws *WS) ReadLoop(msgHandler MsgHandler) error {
	var buf bytes.Buffer
	var opcode Opcode
	for !ws.isClosed {
		frame, err := ws.ReadFrame()
		if err != nil {
			return err
		}
		switch frame.Opcode {
		case OpcodePing:
			log.Println("got ping msg")
			if err := ws.WriteFrame(frame.Payload, OpcodePong, true, false); err != nil {
				return err
			}
		case OpcodePong:
			// ignore
			continue
		case OpcodeClose:
			log.Println("got close msg")
			if err := ws.WriteFrame(frame.Payload, OpcodeClose, true, false); err != nil {
				return err
			}
			ws.isClosed = true
			// close the underlying conn
			ws.conn.Close()
		case OpcodeCont:
			log.Println("got cont msg")
			if frame.Fin {
				buf.Write(frame.Payload)
				log.Printf("got fragmented msg: %v", buf.String())
				msg := Msg{
					Opcode:  opcode,
					Payload: buf.Bytes(),
				}
				if err := msgHandler(&msg, ws); err != nil {
					return err
				}
				if err = ws.bufw.Flush(); err != nil {
					return err
				}
				buf.Reset()
			} else {
				buf.Write(frame.Payload)
			}
		case OpcodeBin, OpcodeText:
			opcode = frame.Opcode
			log.Printf("got data msg: %v\n", string(frame.Payload))
			if frame.Fin {
				msg := Msg{
					Opcode:  opcode,
					Payload: frame.Payload,
				}
				if err := msgHandler(&msg, ws); err != nil {
					return err
				}
				ws.bufw.Flush()
				buf.Reset()
			} else {
				// todo: will it really return error?
				buf.Write(frame.Payload)
			}
		default:
			return ErrUnknownOpcode
		}
	}
	return nil
}

func (ws *WS) WriteMsg(msgType Opcode, payload []byte) error {
	var firstSent bool
	var opcode Opcode
	for len(payload) > msgMaxChunkSize {
		if firstSent {
			opcode = OpcodeCont
		} else {
			opcode = msgType
			firstSent = true
		}
		if err := ws.WriteFrame(payload[:msgMaxChunkSize], opcode, false, ws.isClient); err != nil {
			return err
		}
		payload = payload[msgMaxChunkSize:]
	}

	if firstSent {
		opcode = OpcodeCont
	} else {
		opcode = msgType
	}
	return ws.WriteFrame(payload, opcode, true, ws.isClient)
}

// Code points in the surrogate range are not valid for UTF-8.
const (
	surrogateMin = 0xD800
	surrogateMax = 0xDFFF

	maxRune = '\U0010FFFF' // Maximum valid Unicode code point.
)

const (
	t1 = 0b00000000
	tx = 0b10000000
	t2 = 0b11000000
	t3 = 0b11100000
	t4 = 0b11110000
	t5 = 0b11111000

	maskx = 0b00111111
	mask2 = 0b00011111
	mask3 = 0b00001111
	mask4 = 0b00000111

	rune1Max = 1<<7 - 1
	rune2Max = 1<<11 - 1
	rune3Max = 1<<16 - 1
)

func utf8ToRune(bs []byte) (c rune, size int, err error) {
	maxSize := len(bs)
	if maxSize < 1 {
		err = ErrShortUtf8
		return
	}
	b := bs[0]

	if b&tx == 0 { // 1 byte
		size = 1
		c = rune(b)
		return
	}

	if b&t3 == t2 { // 2 bytes
		if maxSize < 2 {
			err = ErrShortUtf8
			return
		}
		size = 2
		c = (rune(b) & mask2) << 6
		// Overlong sequence or invalid second.
		b = bs[1]
		if c == 0 || b&t2 != tx {
			err = ErrInvalidUtf8Recvd
			return
		}
		c += rune(b) & maskx
		// maximum overlong sequence
		// if c lies in the one byte range
		// then it is a overlong sequence
		if c <= rune1Max {
			err = ErrInvalidUtf8Recvd
			return
		}
		// UTF-16 surrogate pairs
		if surrogateMin <= c && c <= surrogateMax {
			err = ErrInvalidUtf8Recvd
			return
		}
		return
	}

	if b&t4 == t3 { // 3 bytes
		if maxSize < 3 {
			err = ErrShortUtf8
			return
		}
		size = 3
		c = (rune(b) & mask3) << 12
		b = bs[1]
		if b&t2 != tx {
			err = ErrInvalidUtf8Recvd
			return
		}
		c += (rune(b) & maskx) << 6
		b = bs[2]
		// Overlong sequence or invalid last
		if c == 0 || b&t2 != tx {
			err = ErrInvalidUtf8Recvd
			return
		}
		c += rune(b) & maskx
		// NEW: maximum overlong sequence
		if c <= rune2Max {
			err = ErrInvalidUtf8Recvd
			return
		}
		// UTF-16 surrogate pairs
		if surrogateMin <= c && c <= surrogateMax {
			err = ErrInvalidUtf8Recvd
			return
		}
		return
	}
	if maxSize < 4 { // 4 bytes
		err = ErrShortUtf8
		return
	}
	if b&t5 != t4 {
		err = ErrInvalidUtf8Recvd
		return
	}
	size = 4
	c = (rune(b) & mask4) << 18
	b = bs[1]
	if b&t2 != tx {
		err = ErrInvalidUtf8Recvd
		return
	}
	c += (rune(b) & maskx) << 12
	b = bs[2]
	if b&t2 != tx {
		err = ErrInvalidUtf8Recvd
		return
	}
	c += (rune(b) & maskx) << 6
	b = bs[3]
	// Overlong sequence or invalid last
	if c == 0 || b&t2 != tx {
		err = ErrInvalidUtf8Recvd
		return
	}
	c += rune(b) & maskx
	// maximum overlong sequence
	if c <= rune3Max {
		err = ErrInvalidUtf8Recvd
		return
	}
	// UTF-16 surrogate pairs
	if surrogateMin <= c && c <= surrogateMax {
		err = ErrInvalidUtf8Recvd
		return
	}
	// Maximum valid Unicode number
	if c > maxRune {
		err = ErrInvalidUtf8Recvd
		return
	}
	return
}
