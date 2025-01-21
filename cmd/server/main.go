package main

import (
	"log"
	"net"

	"github.com/cs50Mu/gws"
)

const (
	ADDR = "localhost:6969"
)

func main() {
	ln, err := net.Listen("tcp", ADDR)
	if err != nil {
		panic(err)
	}

	log.Printf("listening on: %v\n", ADDR)
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	// handle conn
	ws := gws.NewWS(conn)
	if err := ws.ServerHandshake(); err != nil {
		badRequest(conn)
		return
	}
	log.Println("server handshake done")
	if err := ws.ReadLoop(msgHandler); err != nil {
		log.Printf("ServerLoop failed, err: %v", err)
	}
}

func badRequest(conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
	conn.Write([]byte("\r\n"))
}

func msgHandler(payload []byte, ws *gws.WS) error {
	log.Printf("writing payload in msgHandler: %v\n", string(payload))
	return ws.ServerWriteText(payload, true)
}
