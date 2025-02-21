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
		log.Fatal(err)
	}

	log.Printf("listening on: %v\n", ADDR)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	// handle conn
	ws := gws.NewServerWS(conn)
	if err := ws.ServerHandshake(); err != nil {
		badRequest(conn)
		return
	}
	log.Println("server handshake done")

	// if err := ws.ReadLoop(msgHandler); err != nil {
	// 	log.Printf("ServerLoop failed, err: %v", err)
	// }

	for {
		msgType, payload, err := ws.ReadMsg()
		if err != nil {
			log.Printf("err: %v\n", err)
			return
		}
		log.Printf("[Server] recved msg, type: %v, len: %v\n",
			msgType.String(), len(payload))
		if err := ws.WriteMsg(msgType, payload); err != nil {
			log.Fatal(err)
		}
	}
}

func badRequest(conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
	conn.Write([]byte("\r\n"))
}
