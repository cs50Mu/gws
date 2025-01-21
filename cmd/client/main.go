package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net"

	"github.com/cs50Mu/gws"
)

const (
	// HOST = "echo.websocket.org"
	// PORT = 443
	HOST = "127.0.0.1"
	PORT = 6969
)

func main() {
	// conf := &tls.Config{
	// 	InsecureSkipVerify: true,
	// }
	// addr := fmt.Sprintf("%v:%v", HOST, PORT)
	// conn, err := tls.Dial("tcp", addr, conf)

	addr := fmt.Sprintf("%v:%v", HOST, PORT)
	conn, err := net.Dial("tcp", addr)

	if err != nil {
		panic(err)
	}
	defer conn.Close()

	ws := gws.NewWS(conn)

	err = ws.ClientHandshake(HOST)
	if err != nil {
		panic(err)
	}

	// payload := []byte(nil)
	// opcode := gws.OpcodePing
	// // payload := []byte("hello, websocket!")
	// // opcode := gws.OpcodeText
	// if err = ws.WriteFrame(payload, opcode, true, true); err != nil {
	// 	panic(err)
	// }
	var payload bytes.Buffer
	for i := 0; i < math.MaxUint16; i++ {
		payload.WriteByte('E')
	}
	log.Printf("payloadLen: %v\n", payload.Len())

	if err = ws.ClientWriteText(payload.Bytes(), false); err != nil {
		panic(err)
	}

	if err = ws.ClientWriteText([]byte("world"), true); err != nil {
		panic(err)
	}

	// if err = ws.WriteFrame(nil, gws.OpcodeClose, true, true); err != nil {
	// 	panic(err)
	// }

	if err = ws.ReadLoop(msgHandler); err != nil {
		panic(err)
	}
}

func msgHandler(payload []byte, ws *gws.WS) error {
	return nil
}
