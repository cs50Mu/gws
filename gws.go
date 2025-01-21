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
)

var (
	ErrBadClientHandshake = errors.New("bad client handshake")
	ErrUnknownOpcode      = errors.New("unknown opcode")
	ErrConnClosed         = errors.New("conn is closed")
)

type WS struct {
	conn     net.Conn
	bufw     *bufio.Writer
	bufr     *bufio.Reader
	isClosed bool
	opcode   Opcode
}

func NewWS(conn net.Conn) *WS {
	return &WS{
		conn: conn,
		bufw: bufio.NewWriter(conn),
		bufr: bufio.NewReader(conn),
	}
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
	var first byte
	if isFin {
		first |= 0x1 << 3
	}
	// opcode
	first <<= 4
	first |= byte(opcode)
	buf.WriteByte(first)
	// mask and payloadLen
	payloadLen := len(payload)
	if payloadLen < 126 {
		data := byte(payloadLen)
		if needMask {
			data |= 0x1 << 7
		}
		buf.WriteByte(data)
	} else if payloadLen <= math.MaxUint16 {
		data := byte(126)
		if needMask {
			data |= 0x1 << 7
		}
		buf.WriteByte(data)
		// 2 more bytes
		dataLen := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLen, uint16(payloadLen))
		buf.Write(dataLen)
	} else {
		data := byte(127)
		if needMask {
			data |= 0x1 << 7
		}
		buf.WriteByte(data)
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
	Payload []byte
	IsFin   bool
}

func (ws *WS) ReadFrame() (*Frame, error) {
	first, err := ws.bufr.ReadByte()
	if err != nil {
		return nil, err
	}

	frame := new(Frame)
	isFinal := false
	fin := first >> 7
	if fin == 0x1 {
		isFinal = true
	}
	opcode := first & 0xf
	frame.IsFin = isFinal
	frame.Opcode = Opcode(opcode)
	// second byte
	second, err := ws.bufr.ReadByte()
	if err != nil {
		return nil, err
	}
	isMask := false
	maskBit := second >> 7
	if maskBit == 0x1 {
		isMask = true
	}
	payloadLen := second & (^(byte(0x1) << 7))

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
		// realPayloadlen |= ^(0x1 << 63)
	}

	var mask []byte
	// masking
	if isMask { // 4 bytes
		mask = make([]byte, 4)
		_, err := io.ReadFull(ws.bufr, mask)
		if err != nil {
			return nil, err
		}
	}
	log.Printf("recved payloadLen: %v\n", realPayloadlen)
	// payload
	if realPayloadlen > 0 {
		// todo: make will panic if realPayloadlen is too big
		payload := make([]byte, realPayloadlen)
		_, err = io.ReadFull(ws.bufr, payload)
		if err != nil {
			return nil, err
		}
		// log.Printf("payload: %+v\n", payload)
		if isMask {
			payload = maskUnmask(payload, mask)
		}
		frame.Payload = payload
	}

	return frame, nil
}

type Msg struct {
	Opcode  Opcode
	Payload []byte
}

func (ws *WS) ReadLoop(msgHandler func(payload []byte, ws *WS) error) error {
	var buf bytes.Buffer
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
			if frame.IsFin {
				buf.Write(frame.Payload)
				log.Printf("got fragmented msg: %v", buf.String())
				if err := msgHandler(buf.Bytes(), ws); err != nil {
					return err
				}
				if err = ws.bufw.Flush(); err != nil {
					return err
				}
				buf.Reset()
			} else {
				buf.Write(frame.Payload)
			}
		case OpcodeBin:
		case OpcodeText:
			log.Printf("got data msg: %v\n", string(frame.Payload))
			if frame.IsFin {
				if err := msgHandler(frame.Payload, ws); err != nil {
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

func (ws *WS) WriteData(payload []byte, opcode Opcode, isFin, needMask bool) error {
	if ws.isClosed {
		return ErrConnClosed
	}
	if ws.opcode != 0 {
		opcode = OpcodeCont
	} else {
		ws.opcode = opcode
	}

	return ws.WriteFrame(payload, opcode, isFin, needMask)
}

func (ws *WS) ServerWriteText(payload []byte, isFin bool) error {
	return ws.WriteData(payload, OpcodeText, isFin, false)
}

func (ws *WS) ClientWriteText(payload []byte, isFin bool) error {
	log.Printf("cli sending text: %v\n", string(payload))
	return ws.WriteData(payload, OpcodeText, isFin, true)
}

func (ws *WS) ServerWriteBin(payload []byte, isFin bool) error {
	return ws.WriteData(payload, OpcodeBin, isFin, false)
}

func (ws *WS) ClientWriteBin(payload []byte, isFin bool) error {
	return ws.WriteData(payload, OpcodeBin, isFin, true)
}
