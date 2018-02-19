package main

import (
	"./serverdfs"
	"os"
	"net/rpc"
	"net"
	"log"
)

func main() {
	args := os.Args[1:]

	if len(args) != 1 {
		log.Fatalf("Usage: go run server.go [client-incoming ip:port]")
		return
	}
	server_port := args[0]
	DfsS := new(serverdfs.DfsServer)
	DfsS.ServerPort = server_port
	server := rpc.NewServer()
	err := server.RegisterName("DFSServer", DfsS)
	if err != nil {
		log.Fatalf("%v", err)
	}

	l, err := net.Listen("tcp", server_port)
	if err != nil {
		log.Fatalf("DFS Server: Unavailable port [%s]", server_port)
		return
	}
	log.Printf("Accepting connections on port [%s] \n", server_port)
	server.Accept(l)
}


