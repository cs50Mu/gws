# Websocket library in Golang

A simple websocket library written in Golang

## Testing

It passed most of the Autobahn WebSocket Testsuite test cases.

In one terminal:
```console
cd cmd/server
go run main.go
```

In another terminal:
```console
wstest -m fuzzingclient
```
