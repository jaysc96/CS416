/*
Implements the solution to assignment 1 for UBC CS 416 2017 W2.

Usage:
$ go run client.go [local UDP ip:port] [local TCP ip:port] [aserver UDP ip:port]

Example:
$ go run client.go 198.162.33.54:8975 198.162.33.54:8354 142.103.15.6:6666

*/

package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

/////////// Msgs used by both auth and fortune servers:

// An error message from the server.
type ErrMessage struct {
	Error string
}

/////////// Auth server msgs:

// Message containing a nonce from auth-server.
type NonceMessage struct {
	Nonce string
	N     int64 // PoW difficulty: number of zeroes expected at end of md5(nonce+secret)
}

// Message containing an the secret value from client to auth-server.
type SecretMessage struct {
	Secret string
}

// Message with details for contacting the fortune-server.
type FortuneInfoMessage struct {
	FortuneServer string // TCP ip:port for contacting the fserver
	FortuneNonce  int64
}

/////////// Fortune server msgs:

// Message requesting a fortune from the fortune-server.
type FortuneReqMessage struct {
	FortuneNonce int64
}

// Response from the fortune-server containing the fortune.
type FortuneMessage struct {
	Fortune string
	Rank    int64 // Rank of this client solution
}

// Main workhorse method.
func main() {
	// get arguments and take secret from user
	args := os.Args[1:]

	if len(args) != 3 {
		log.Fatalln("Usage: go run client.go [local UDP ip:port] [local TCP ip:port] [aserver UDP ip:port]")
		return
	}

	local_udp_port := args[0]
	local_tcp_port := args[1]
	aserver_udp_port := args[2]

	// Resolve UDP addresses
	laddr_udp, err := net.ResolveUDPAddr("udp", local_udp_port)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	raddr_udp, err := net.ResolveUDPAddr("udp", aserver_udp_port)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	// UDP connection to aserver
	udpconn, err := net.DialUDP("udp", laddr_udp, raddr_udp)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	defer udpconn.Close()

	arbitrary := "this is an arbitrary string"
	b, err := json.Marshal(arbitrary)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	// Write to aserver
	i, err := udpconn.Write(b)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	// Create buffer to read aserver's reply
	buf := make([]byte, 1024)
	i, err = udpconn.Read(buf)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	n := mycopy(buf, i)

	var nonce NonceMessage
	err = json.Unmarshal(n, &nonce)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	// Generate comparison string
	var comp, s string
	for i = 0; i < int(nonce.N); i++ {
		comp += "0"
	}

	// Compute secret using brute-force
	for n := 0; ; n++ {
		s = strconv.Itoa(n)
		hash := computeNonceSecretHash(nonce.Nonce, s)
		if strings.Compare(hash[len(hash)-int(nonce.N):], comp) == 0 {
			break
		}
	}

	secret := SecretMessage{s}

	b, err = json.Marshal(secret)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	i, err = udpconn.Write(b)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	i, err = udpconn.Read(buf)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	n = mycopy(buf, i)

	var fortune_info FortuneInfoMessage
	var err_message ErrMessage
	err = json.Unmarshal(n, &fortune_info)
	if err != nil {
		err = json.Unmarshal(n, &err_message)
		if err != nil {
			log.Fatalf("%v", err)
			return
		}
		log.Fatalf("%s", err_message.Error)
		return
	}

	fserver_tcp_port := fortune_info.FortuneServer
	fortune_req := FortuneReqMessage{fortune_info.FortuneNonce}

	// Resolve TCP addresses
	laddr_tcp, err := net.ResolveTCPAddr("tcp", local_tcp_port)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	raddr_tcp, err := net.ResolveTCPAddr("tcp", fserver_tcp_port)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	// TCP connection to server
	tcpconn, err := net.DialTCP("tcp", laddr_tcp, raddr_tcp)
	b, err = json.Marshal(fortune_req)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	defer tcpconn.Close()

	i, err = tcpconn.Write(b)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}

	i, err = tcpconn.Read(buf)
	if err != nil {
		log.Fatalf("%v", err)
		return
	}
	n = mycopy(buf, i)

	var fortune_message FortuneMessage
	err = json.Unmarshal(n, &fortune_message)
	if err != nil {
		err = json.Unmarshal(n, &err_message)
		if err != nil {
			log.Fatalf("%v", err)
			return
		}
		log.Fatalf("%s", err_message.Error)
		return
	}
	fmt.Println(fortune_message.Fortune)
}

// Returns the MD5 hash as a hex string for the (nonce + secret) value.
func computeNonceSecretHash(nonce string, secret string) string {
	h := md5.New()
	h.Write([]byte(nonce + secret))
	str := hex.EncodeToString(h.Sum(nil))
	return str
}

// copies i elements from buf[] to new byte[]
func mycopy(buf []byte, i int) []byte {
	new_buf := make([]byte, i)
	for p := 0; p < i; p++ {
		new_buf[p] = buf[p]
	}
	return new_buf
}
