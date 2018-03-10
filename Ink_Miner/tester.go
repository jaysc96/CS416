/*

Simple set of tests for server.go used in project 1 of UBC CS 416
2017W2. Runs through the server's RPCs and their error codes.

Usage:

$ go run tester.go
  -b int
    	Heartbeat interval in ms (default 10)
  -i string
    	RPC server ip:port
  -p int
    	start port (default 54320)

*/

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"time"
)

type MinerInfo struct {
	Address net.Addr
	Key     ecdsa.PublicKey
}

// Settings for a canvas in BlockArt.
type CanvasSettings struct {
	// Canvas dimensions
	CanvasXMax uint32 `json:"canvas-x-max"`
	CanvasYMax uint32 `json:"canvas-y-max"`
}

type MinerSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string `json:"genesis-block-hash"`

	// The minimum number of ink miners that an ink miner should be
	// connected to.
	MinNumMinerConnections uint8 `json:"min-num-miner-connections"`

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32 `json:"ink-per-op-block"`
	InkPerNoOpBlock uint32 `json:"ink-per-no-op-block"`

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32 `json:"heartbeat"`

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8 `json:"pow-difficulty-op-block"`
	PoWDifficultyNoOpBlock uint8 `json:"pow-difficulty-no-op-block"`
}

// Settings for an instance of the BlockArt project/network.
type MinerNetSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string `json:"genesis-block-hash"`

	// The minimum number of ink miners that an ink miner should be
	// connected to.
	MinNumMinerConnections uint8 `json:"min-num-miner-connections"`

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32 `json:"ink-per-op-block"`
	InkPerNoOpBlock uint32 `json:"ink-per-no-op-block"`

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32 `json:"heartbeat"`

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8 `json:"pow-difficulty-op-block"`
	PoWDifficultyNoOpBlock uint8 `json:"pow-difficulty-no-op-block"`

	// Canvas settings
	CanvasSettings CanvasSettings `json:"canvas-settings"`
}

func exitOnError(prefix string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s, err = %s\n", prefix, err.Error())
		os.Exit(1)
	}
}

var ExpectedError = errors.New("Expected error, none found")

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	ipPort := flag.String("i", "", "RPC server ip:port")
	startPort := flag.Int("p", 54320, "start port")
	heartBeat := flag.Int("b", 10, "Heartbeat interval in ms")
	flag.Parse()
	if *ipPort == "" || *startPort <= 1024 || *heartBeat <= 0 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// heartBeatInterval := time.Duration(*heartBeat) * time.Millisecond
	twoHeartBeatIntervals := time.Duration(*heartBeat*2) * time.Millisecond

	r, err := os.Open("/dev/urandom")
	exitOnError("open /dev/urandom", err)
	defer r.Close()

	priv1, err := ecdsa.GenerateKey(elliptic.P384(), r)
	exitOnError("generate key 1", err)
	priv2, err := ecdsa.GenerateKey(elliptic.P384(), r)
	exitOnError("generate key 2", err)

	addr1, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", *startPort))
	exitOnError("resolve addr 1", err)
	addr2, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", *startPort+1))
	exitOnError("resolve addr2", err)

	c, err := rpc.Dial("tcp", *ipPort)
	exitOnError("rpc dial", err)
	defer c.Close()

	var settings MinerNetSettings
	var _ignored bool

	// normal registration
	err = c.Call("RServer.Register", MinerInfo{Address: addr1, Key: priv1.PublicKey}, &settings)
	exitOnError(fmt.Sprintf("client registration for %s", addr1.String()), err)
	err = c.Call("RServer.Register", MinerInfo{Address: addr2, Key: priv2.PublicKey}, &settings)
	exitOnError(fmt.Sprintf("client registration for %s", addr2.String()), err)
	time.Sleep(twoHeartBeatIntervals)

	// late heartbeat
	err = c.Call("RServer.Register", MinerInfo{Address: addr1, Key: priv1.PublicKey}, &settings)
	exitOnError(fmt.Sprintf("client registration for %s", addr1.String()), err)
	time.Sleep(twoHeartBeatIntervals)
	err = c.Call("RServer.HeartBeat", priv1.PublicKey, &_ignored)
	if err == nil {
		exitOnError("late heartbeat", ExpectedError)
	}

	// register twice with same address
	err = c.Call("RServer.Register", MinerInfo{Address: addr1, Key: priv1.PublicKey}, &settings)
	exitOnError(fmt.Sprintf("client registration for %s", addr1.String()), err)
	err = c.Call("RServer.Register", MinerInfo{Address: addr1, Key: priv2.PublicKey}, &settings)
	if err == nil {
		exitOnError("registering twice with the same address", ExpectedError)
	}
	time.Sleep(twoHeartBeatIntervals)

	// register twice with same key
	err = c.Call("RServer.Register", MinerInfo{Address: addr1, Key: priv1.PublicKey}, &settings)
	exitOnError(fmt.Sprintf("client registration for %s", addr1.String()), err)
	err = c.Call("RServer.Register", MinerInfo{Address: addr2, Key: priv1.PublicKey}, &settings)
	if err == nil {
		exitOnError("registering twice with the same key", ExpectedError)
	}
}
