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

// Close the websocket and underlying conn.
// must close the conn as follows, or may
// lose data
// refer: https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
// also many thanks to Mr Zozin: https://www.youtube.com/watch?v=JRTLSxGf_6w
func (ws *WS) Close() {
	c := ws.conn.(*net.TCPConn)
	// shutdown the writing side of the conn
	// Informing the OS that we are not planning to send anything anymore
	c.CloseWrite()
	// drain the conn.
	// Depleting input before closing socket, so the OS does not send
	// RST just because we have some input pending on close
	buf := make([]byte, 1024)
	for {
		_, err := c.Read(buf)
		if err != nil {
			break
		}
	}
	// Actually destroying the socket
	c.Close()
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
		maskUnmask(payload, mask, 0)
	}
	buf.Write(payload)

	ws.bufw.Write(buf.Bytes())
	return ws.bufw.Flush()
}

func maskUnmask(payload, mask []byte, idx uint64) {
	for i := 0; i < len(payload); i++ {
		payload[i] = payload[i] ^ mask[(idx+uint64(i))%4]
	}
}

type FrameHeader struct {
	Opcode     Opcode
	Fin        bool
	Rsv1       bool
	Rsv2       bool
	Rsv3       bool
	Masked     bool
	MaskKey    []byte
	PayloadLen uint64
}

func (ws *WS) readFrameHeader() (*FrameHeader, error) {
	data := make([]byte, 2)
	_, err := io.ReadFull(ws.bufr, data)
	if err != nil {
		return nil, err
	}

	frame := &FrameHeader{
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
		_ = ws.WriteFrame(nil, OpcodeClose, true, false)
		return nil, ErrExtensionNotNegotiated
	}

	payloadLen := data[1] & 0x7f
	// RFC 6455 - Section 5.5: Control Frames
	//   All control frames MUST have a payload length of 125 bytes or less
	//   and MUST NOT be fragmented.
	if frame.Opcode.isControl() && (payloadLen > 125 || !frame.Fin) {
		_ = ws.WriteFrame(nil, OpcodeClose, true, false)
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

	frame.PayloadLen = realPayloadlen
	var mask []byte
	// masking
	if frame.Masked { // 4 bytes
		mask = make([]byte, 4)
		_, err := io.ReadFull(ws.bufr, mask)
		if err != nil {
			return nil, err
		}
		frame.MaskKey = mask
	}
	log.Printf("recved payloadLen: %v\n", realPayloadlen)
	return frame, nil
}

func (ws *WS) readFramePayloadChunk(frame *FrameHeader, payload []byte, idx uint64) (int, error) {
	n, err := ws.bufr.Read(payload)
	if err != nil {
		return 0, err
	}
	if frame.Masked {
		maskUnmask(payload[:n], frame.MaskKey, idx)
	}
	return n, nil
}

func (ws *WS) readFramePayload(frame *FrameHeader) ([]byte, error) {
	var payload []byte
	// log.Printf("frame: %+v\n", frame)
	if frame.PayloadLen > 0 {
		payload = make([]byte, frame.PayloadLen)
		idx := uint64(0) // the index of the payload to write for the next Read
		for idx < frame.PayloadLen {
			n, err := ws.readFramePayloadChunk(frame, payload[idx:], idx)
			if err != nil {
				return nil, err
			}
			idx += uint64(n)
		}
	}
	return payload, nil
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
func (ws *WS) ReadMsg() (msgType Opcode, msgPayload []byte, err error) {
	var header *FrameHeader
	var buf bytes.Buffer
	var framePayload []byte
	verifyIdx := 0
	for {
		header, err = ws.readFrameHeader()
		if err != nil {
			return
		}

		switch header.Opcode {
		case OpcodeText, OpcodeBin:
			// all data frames after the initial
			// data frame must have opcode 0.
			if msgType != OpcodeCont {
				_ = ws.WriteFrame(nil, OpcodeClose, true, false)
				err = ErrBadFrameRecvd
				return
			}
			msgType = header.Opcode
		}
		if !header.Opcode.isControl() && msgType == OpcodeText && header.PayloadLen > 0 {
			framePayload = make([]byte, header.PayloadLen)
			idx := uint64(0) // the index of the payload to write for the next Read
			var n int
			for idx < header.PayloadLen {
				n, err = ws.readFramePayloadChunk(header, framePayload[idx:], idx)
				if err != nil {
					return
				}
				buf.Write(framePayload[idx : idx+uint64(n)])
				idx += uint64(n)
				// check utf8
				// RFC 6455 - Section 8.1: Handling Errors in UTF-8-Encoded Data
				//   When an endpoint is to interpret a byte stream as UTF-8 but finds
				//   that the byte stream is not, in fact, a valid UTF-8 stream, that
				//   endpoint MUST _Fail the WebSocket Connection_.
				//
				// In order to fail fast on invalid utf8 byte stream, we need to check
				// the bytes by tcp chunk, but actually the fail fast "feature" is not
				// required by the rfc, it is from the Autobahn Websocket Testsuite
				// refer to: Autobahn WebSocket Testsuite Case 6.4.*
				msgCurr := buf.Bytes()
				for verifyIdx < buf.Len() {
					_, size, parseErr := utf8ToRune(msgCurr[verifyIdx:])
					// log.Printf("char: %c, size: %v, err: %v\n", c, size, parseErr)
					if parseErr != nil {
						if parseErr == ErrShortUtf8 && !header.Fin {
							log.Println("got short utf8, extending it..")
							oldPayloadLen := buf.Len()
							// make the short utf8 byte stream
							// complete with a bunch of zeros
							extendUtf8Bytes(verifyIdx, &buf)
							msgCurr = buf.Bytes()
							log.Println("extended, verify again")
							// and check it again, now it will be a
							// complete utf8 byte sequence if it is
							// still not a valid utf8 byte sequence,
							// return err immediately, in which case,
							// the byte sequence encodes an invalid
							// code point(either too large or in the
							// surrogate range)
							_, _, parseErr = utf8ToRune(msgCurr[verifyIdx:])
							if parseErr != nil {
								_ = ws.WriteFrame(nil, OpcodeClose, true, false)
								err = ErrInvalidUtf8Recvd
								return
							}
							buf.Truncate(oldPayloadLen)
							break
						} else {
							_ = ws.WriteFrame(nil, OpcodeClose, true, false)
							err = ErrInvalidUtf8Recvd
							return
						}
					}
					verifyIdx += size
				}
			}
		} else {
			framePayload, err = ws.readFramePayload(header)
			if err != nil {
				return
			}
		}
		// payload has been fullly read by now
		switch header.Opcode {
		case OpcodePing:
			log.Println("got ping msg")
			if err = ws.WriteFrame(framePayload, OpcodePong, true, false); err != nil {
				return
			}
		case OpcodePong:
			// ignore
			continue
		case OpcodeClose:
			log.Println("got close msg")
			if len(framePayload) > 0 {
				statusCode, reason, err := parseCloseFrameBody(framePayload)
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
			_ = ws.WriteFrame(framePayload, OpcodeClose, true, false)
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
			// buf.Write(framePayload)
			// log.Println("got cont msg")
			if header.Fin {
				msgPayload = make([]byte, buf.Len())
				copy(msgPayload, buf.Bytes()) // need deep copy
				buf.Reset()
				verifyIdx = 0
				return
			}
		case OpcodeBin, OpcodeText:
			if header.Fin {
				msgPayload = framePayload
				buf.Reset()
				return
			}
		default:
			_ = ws.WriteFrame(nil, OpcodeClose, true, false)
			err = ErrUnknownOpcode
			return
		}
	}
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

func hexPrint(bs []byte) string {
	var buffer strings.Builder
	for _, b := range bs {
		buffer.WriteString(fmt.Sprintf("\\x%X", b))
	}
	return buffer.String()
}

func utf8ToRune(bs []byte) (c rune, size int, err error) {
	// log.Printf("bs: %v\n", hexPrint(bs))
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
	} // it must be a 4 bytes utf8 stream, or error
	if b&t5 != t4 {
		err = ErrInvalidUtf8Recvd
		return
	}
	if maxSize < 4 { // 4 bytes
		err = ErrShortUtf8
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

// extendUtf8Bytes extend `bs` so that it
// looks like a valid utf8 encoded bytes stream
//
// fill the missing bytes with zeros
func extendUtf8Bytes(verifyIdx int, buf *bytes.Buffer) {
	log.Printf("old buf len: %v, verifyIndex: %v\n", buf.Len(), verifyIdx)
	bs := buf.Bytes()
	first := bs[verifyIdx]
	var size int
	switch {
	// only size which is greater than 2 bytes may need to extend
	case first&t3 == t2: // 2 bytes
		size = 2
	case first&t4 == t3: // 3 bytes
		size = 3
	case first&t5 == t4: // 4 bytes
		size = 4
	}
	log.Printf("size: %v\n", size)

	extra := size - (buf.Len() - verifyIdx)
	log.Printf("extra: %v\n", extra)
	buf.Grow(extra)
	for extra > 0 {
		buf.WriteByte(tx)
		extra--
	}
}
