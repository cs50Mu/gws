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

	ws := gws.NewClientWS(conn)

	err = ws.ClientHandshake(HOST)
	if err != nil {
		panic(err)
	}

	var payload bytes.Buffer
	for i := 0; i < math.MaxUint16; i++ {
		payload.WriteByte('E')
	}
	log.Printf("payloadLen: %v\n", payload.Len())

	// if err = ws.WriteMsg(gws.OpcodeText, payload.Bytes()); err != nil {
	// 	panic(err)
	// }
	if err = ws.WriteMsg(gws.OpcodeText, []byte("hello, from websocket")); err != nil {
		log.Fatal(err)
	}

	if err = ws.WriteMsg(gws.OpcodeText, []byte("world")); err != nil {
		log.Fatal(err)
	}

	if err = ws.WriteMsg(gws.OpcodeBin, []byte{0xff, 0x00, 0x11}); err != nil {
		log.Fatal(err)
	}

	for {
		msgType, payload, err := ws.ReadMsg()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("[client] recved msg, type: %v, payload: %+v\n", msgType.String(), payload)
	}
}
