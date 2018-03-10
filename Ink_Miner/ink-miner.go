package main

import (
	"os"
	"log"
	"net/rpc"
	"net"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"time"
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"crypto/x509"
	"math/big"
	"fmt"
	"strings"
	"math"
)

// Contains the bad shape hash string.
type InvalidShapeHashError string

func (e InvalidShapeHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid shape hash [%s]", string(e))
}

// Contains amount of ink remaining.
type InsufficientInkError uint32

func (e InsufficientInkError) Error() string {
	return fmt.Sprintf("BlockArt: Not enough ink to addShape [%d]", uint32(e))
}

// Contains the bad shape hash string.
type ShapeOwnerError string

func (e ShapeOwnerError) Error() string {
	return fmt.Sprintf("BlockArt: Shape owned by someone else [%s]", string(e))
}

// Contains the hash of the shape that this shape overlaps with.
type ShapeOverlapError string

func (e ShapeOverlapError) Error() string {
	return fmt.Sprintf("BlockArt: Shape overlaps with a previously added shape [%s]", string(e))
}

// Contains the invalid block hash.
type InvalidBlockHashError string

func (e InvalidBlockHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid block hash [%s]", string(e))
}

// Contains invalid key
type InvalidKeyError string

func (e InvalidKeyError) Error() string {
	return fmt.Sprintf("InkMiner: Key could not be verified")
}

// Contains the offending block string.
type ProofOfWorkInvalidError string

func (e ProofOfWorkInvalidError) Error() string {
	return fmt.Sprintf("InkMiner: PoW invalid [%s]", string(e))
}

// Contains offending parent block hash
type ParentBlockDoesntExistError string

func (e ParentBlockDoesntExistError) Error() string {
	return fmt.Sprintf("InkMiner: Parent hash doesn't exist [%s]", string(e))
}

type InkMiner struct {
	Key ecdsa.PrivateKey
	Ink uint32
	NumNeighbours int
	Neighbours map[net.Addr]*rpc.Client
	Settings MinerNetSettings
	BlockChain BlockChain
	CurrentOps map[string]Operation
	CompletedOps map[string]Operation
	IsMining bool
}

type INKMiner interface {
	VerifyArtNode(node SignedNodeHash, cs *CanvasSettings) error
	AccessBlockChain(old_chain BlockChain, new_chain *BlockChain) error
	GetBlock(hash string, block *Block) error
	GetGenesisBlock(key ecdsa.PublicKey, block_hash *string) error
	GetChildren(hash string, children *[]Block) error
	ValidateAndPushBlock(block Block, _pushed *bool) error
	GetInk(key ecdsa.PublicKey, ink *uint32) error
	PerformOperation(node_op NodeOp, block_hash *string) error
	GetSVGString(shape_hash string, operation *Operation) error
	GetShapes(block_hash string, operations *[]Operation) error

	monitorNodeState(server *rpc.Client)
	mineOpBlock()
	mineNoOpBlock()
	isValidOperation(operation Operation) bool
}

type SignedNodeHash struct {
	R, S *big.Int
}

type Block struct {
	PrevHash string
	Ops map[string]Operation
	MinerKey ecdsa.PublicKey
	Nonce uint32
	Hash string
	BlockNumInChain int
}

type BlockChain struct {
	Blocks map[string]Block
	LastBlockInChain *Block
	LongestChainLen int
}

type Operation struct {
	Op string
	OpSig string
	NodeKey ecdsa.PublicKey
	Ink uint32
	IsAdd bool
}

type NodeOp struct {
	Op string
	SignedOpSig SignedNodeHash
	ValidateNum uint8
	InkRequired uint32
}

type MinerInfo struct {
	Address net.Addr
	Key     ecdsa.PublicKey
}

type CanvasSettings struct {
	// Canvas dimensions
	CanvasXMax uint32
	CanvasYMax uint32
}

type MinerNetSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string

	// The minimum number of ink miners that an ink miner should be
	// connected to.
	MinNumMinerConnections uint8

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32
	InkPerNoOpBlock uint32

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8
	PoWDifficultyNoOpBlock uint8

	// Canvas settings
	CanvasSettings CanvasSettings
}

func main() {
	gob.Register(&net.TCPAddr{})
	gob.Register(&elliptic.CurveParams{})

	args := os.Args[1:]
	if len(args) != 3 {
		log.Fatalf("Usage: go run ink-miner.go [server ip:port] [pubKey] [privKey]")
		return
	}

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()

	server_addr := args[0]
	pub_key := args[1]
	priv_key := args[2]
	priv_bytes, _ := hex.DecodeString(priv_key)
	PrivKey, _ := x509.ParseECPrivateKey(priv_bytes)
	pub_bytes, _ := x509.MarshalPKIXPublicKey(&PrivKey.PublicKey)
	PubKey := hex.EncodeToString(pub_bytes)
	if PubKey != pub_key {
		log.Fatalf("Private key's public key %s \n differs from Public key %s", PubKey, pub_key)
		return
	}

	conn, err = net.Dial("tcp", server_addr)
	if err != nil {
		log.Fatalf("Error: %s", err)
		return
	}
	defer conn.Close()

	client := rpc.NewClient(conn)
	defer client.Close()

	server := rpc.NewServer()
	IM := new(InkMiner)
	IM.Neighbours = make(map[net.Addr]*rpc.Client)
	IM.BlockChain.Blocks = make(map[string]Block)
	IM.BlockChain.LastBlockInChain = new(Block)
	IM.BlockChain.LongestChainLen = -1
	IM.Key = *PrivKey
	IM.CurrentOps = make(map[string]Operation)
	IM.CompletedOps = make(map[string]Operation)
	IM.IsMining = false

	l, err := net.Listen("tcp", localAddr.IP.String()+":0")
	local_addr := l.Addr()
	log.Printf("InkMiner server running on: %s", local_addr.String())

	miner_net_settings := new(MinerNetSettings)
	err = client.Call("RServer.Register", MinerInfo{local_addr, PrivKey.PublicKey}, miner_net_settings)
	if err != nil {
		log.Fatalf("Error: %s", err)
		return
	}
	IM.Settings = *miner_net_settings

	go initiateHeartbeats(PrivKey.PublicKey, miner_net_settings.HeartBeat, client)
	server.Register(IM)
	go acceptConns(l, server)

	IM.monitorNodeState(client)
}

func (IM *InkMiner) monitorNodeState(server *rpc.Client) {
	for ;true; {
		if IM.NumNeighbours < int(IM.Settings.MinNumMinerConnections) {
			var neighbours []net.Addr
			err := server.Call("RServer.GetNodes", IM.Key.PublicKey, &neighbours)
			if err != nil {
				log.Fatalf("Error: %s", err)
				return
			}
			if len(neighbours) > 0 {
				clients := registerNeighbours(neighbours)
				for a, c := range clients {
					if _, ok := IM.Neighbours[a]; ok {
						delete(clients, a)
					} else {
						IM.Neighbours[a] = c
					}
				}
				IM.NumNeighbours = len(IM.Neighbours) + len(clients)
				chain := getLongestBlockChain(IM.Neighbours)
				if chain.LongestChainLen > IM.BlockChain.LongestChainLen {
					IM.BlockChain = chain
					if !IM.IsMining {
						IM.IsMining = true
						go IM.mineNoOpBlock()
					}
				}
			}
			if IM.BlockChain.LongestChainLen < 0 {
				genBlock := Block{"", nil, IM.Key.PublicKey, 0, IM.Settings.GenesisBlockHash, 0}
				IM.BlockChain.Blocks[IM.Settings.GenesisBlockHash] = genBlock
				*IM.BlockChain.LastBlockInChain = genBlock
				IM.BlockChain.LongestChainLen = 0
				IM.IsMining = true
				go IM.mineNoOpBlock()
			}
		}
		time.Sleep(time.Duration(2)*time.Second)
	}
}

func getLongestBlockChain(clients map[net.Addr]*rpc.Client) BlockChain {
	bc := BlockChain{make(map[string]Block), nil, -1}
	for _, c := range clients {
		err := c.Call("InkMiner.AccessBlockChain", bc, &bc)
		if err != nil {
			continue
		}
	}
	return bc
}

func (IM *InkMiner) AccessBlockChain(old_chain BlockChain, new_chain *BlockChain) error {
	if IM.BlockChain.LongestChainLen > old_chain.LongestChainLen {
		*new_chain = IM.BlockChain
		return nil
	}
	IM.BlockChain = old_chain
	*new_chain = old_chain
	return nil
}

func (IM *InkMiner) GetGenesisBlock(key ecdsa.PublicKey, block_hash *string) error {
	if isSamePublicKey(key, IM.Key.PublicKey) {
		for h, b := range IM.BlockChain.Blocks {
			if b.PrevHash == "" {
				*block_hash = h
				return nil
			}
		}
	}
	return InvalidKeyError("")
}

func (IM *InkMiner) GetBlock(hash string, block *Block) error {
	if bl, ok := IM.BlockChain.Blocks[hash]; ok {
		*block = bl
		return nil
	} else {
		return InvalidBlockHashError(hash)
	}
}

func (IM *InkMiner) GetSVGString(shape_hash string, operation *Operation) error {
	for _, block := range IM.BlockChain.Blocks {
		for opsig, op := range block.Ops {
			if opsig == shape_hash {
				*operation = op
				return nil
			}
		}
	}
	return InvalidShapeHashError(shape_hash)
}

func (IM *InkMiner) GetShapes(block_hash string, operations *[]Operation) error {
	if block, ok := IM.BlockChain.Blocks[block_hash]; ok {
		if block.Ops != nil {
			for _, op := range block.Ops {
				*operations = append(*operations, op)
			}
			return nil
		}
		return InvalidBlockHashError(block_hash)
	} else {
		return InvalidBlockHashError(block_hash)
	}
}

func (IM *InkMiner) GetChildren(hash string, children *[]Block) error {
	for _, block := range IM.BlockChain.Blocks {
		if hash == block.PrevHash {
			*children = append(*children, block)
		}
	}
	if len(*children) == 0 {
		return InvalidBlockHashError(hash)
	}
	return nil
}

func (IM *InkMiner) GetInk(key ecdsa.PublicKey, ink *uint32) error {
	if isSamePublicKey(key, IM.Key.PublicKey) {
		*ink = IM.Ink
		return nil
	}
	return InvalidKeyError("")
}

func isSamePublicKey(key1 ecdsa.PublicKey, key2 ecdsa.PublicKey) bool {
	key1_bytes, _ := x509.MarshalPKIXPublicKey(&key1)
	key2_bytes, _ := x509.MarshalPKIXPublicKey(&key2)
	key1_string := hex.EncodeToString(key1_bytes)
	key2_string := hex.EncodeToString(key2_bytes)
	if key1_string == key2_string {
		return true
	}
	return false
}

func registerNeighbours(addrs []net.Addr) map[net.Addr]*rpc.Client {
	c := make(map[net.Addr]*rpc.Client)
	for i := range addrs {
		cli, err := rpc.Dial(addrs[i].Network(), addrs[i].String())
		if err != nil {
			continue
		}
		c[addrs[i]] = cli
	}
	return c
}

func (IM *InkMiner) VerifyArtNode(node SignedNodeHash, cs *CanvasSettings) error {
	r, s := node.R, node.S
	if ecdsa.Verify(&IM.Key.PublicKey, []byte("Initiate Art Node"), r, s) {
		log.Println("Serving new Art node.")
		*cs = IM.Settings.CanvasSettings
		return nil
	}
	return InvalidKeyError("key")
}

func (IM *InkMiner) mineNoOpBlock() {
	var comp string
	d := int(IM.Settings.PoWDifficultyNoOpBlock)
	for i := 0; i < d; i++ {
		comp += "0"
	}
	chain_len := IM.BlockChain.LongestChainLen
	for n := 0; ; n++ {
		if len(IM.CurrentOps) > 0 {
			return
		}
		if chain_len < IM.BlockChain.LongestChainLen {
			n = 0
			chain_len = IM.BlockChain.LongestChainLen
			continue
		}

		nonce := strconv.Itoa(n)
		h := md5.New()
		key, _ := x509.MarshalPKIXPublicKey(IM.Key.PublicKey)
		h.Write([]byte(IM.BlockChain.LastBlockInChain.Hash + hex.EncodeToString(key) + nonce))
		hash := hex.EncodeToString(h.Sum(nil))

		if hash[len(hash)-d:] == comp {
			block := Block{IM.BlockChain.LastBlockInChain.Hash, nil, IM.Key.PublicKey, uint32(n), hash, IM.BlockChain.LongestChainLen+1}
			var _pushed bool
			IM.IsMining = false
			err := IM.ValidateAndPushBlock(block, &_pushed)
			if err != nil || !_pushed {
				n = 0
				IM.IsMining = true
				continue
			}
			IM.Ink += IM.Settings.InkPerNoOpBlock
			break
		}
	}
}

func (IM *InkMiner) mineOpBlock() {
	num_ops := len(IM.CurrentOps)
	var comp string
	d := int(IM.Settings.PoWDifficultyOpBlock)
	for i := 0; i < d; i++ {
		comp += "0"
	}
	chain_len := IM.BlockChain.LongestChainLen
	for n := 0; ; n++ {
		if len(IM.CurrentOps) == 0 {
			go IM.mineNoOpBlock()
			break
		}
		if num_ops != len(IM.CurrentOps) {
			n = 0
			num_ops = len(IM.CurrentOps)
			continue
		}
		if chain_len < IM.BlockChain.LongestChainLen {
			ops := IM.BlockChain.LastBlockInChain.Ops
			for opsig, op := range ops {
				if _, ok := IM.CurrentOps[opsig]; ok {
					IM.CompletedOps[opsig] = op
					delete(IM.CurrentOps, opsig)
				}
			}
			n = 0
			chain_len = IM.BlockChain.LongestChainLen
			continue
		}

		nonce := strconv.Itoa(n)
		h := md5.New()
		key, _ := x509.MarshalPKIXPublicKey(IM.Key.PublicKey)
		opHash := getOpsHash(IM.CurrentOps)
		h.Write([]byte(IM.BlockChain.LastBlockInChain.Hash + opHash + hex.EncodeToString(key) + nonce))
		hash := hex.EncodeToString(h.Sum(nil))

		if hash[len(hash)-d:] == comp {
			block := Block{IM.BlockChain.LastBlockInChain.Hash, IM.CurrentOps, IM.Key.PublicKey, uint32(n), hash, IM.BlockChain.LongestChainLen+1}
			var _pushed bool
			IM.IsMining = false
			err := IM.ValidateAndPushBlock(block, &_pushed)
			if err != nil || !_pushed {
				n = 0
				IM.IsMining = true
				continue
			}
			IM.Ink += IM.Settings.InkPerOpBlock
			for opsig, op := range IM.CurrentOps {
				IM.CompletedOps[opsig] = op
				delete(IM.CurrentOps, opsig)
			}
			break
		}
	}
}

func getOpsHash(ops map[string]Operation) string {
	hash := ""
	for _, op := range ops {
		key, _ := x509.MarshalPKIXPublicKey(&op.NodeKey)
		hash += op.Op+op.OpSig+hex.EncodeToString(key)
	}
	return hash
}

func (IM *InkMiner) PerformOperation(node_op NodeOp, block_hash *string) error {
	r, s := node_op.SignedOpSig.R, node_op.SignedOpSig.S
	opsig := r.String()+s.String()
	isAdd := true
	opstr := node_op.Op
	inkReq := node_op.InkRequired

	if r == big.NewInt(0) && s == big.NewInt(0) {
		isAdd = false
		if op, ok := IM.CompletedOps[opstr]; !ok {
			return InvalidShapeHashError(opstr)
		} else {
			if !isSamePublicKey(op.NodeKey, IM.Key.PublicKey) {
				key_bytes, _ := x509.MarshalPKIXPublicKey(&op.NodeKey)
				return ShapeOwnerError(hex.EncodeToString(key_bytes))
			}
			opsig = IM.CompletedOps[opstr].Op
			inkReq = IM.CompletedOps[opstr].Ink
		}
	} else if inkReq > IM.Ink {
		return InsufficientInkError(IM.Ink)
	}

	if !ecdsa.Verify(&IM.Key.PublicKey, []byte(opstr), r, s) {
		return InvalidKeyError("")
	}

	op := Operation{opstr, opsig, IM.Key.PublicKey, inkReq, isAdd}
	if IM.isValidOperation(op) {
		if isAdd {
			IM.Ink -= inkReq
		} else {
			IM.Ink += inkReq
		}

		for a, c := range IM.Neighbours {
			call := c.Go("InkMiner.PerformNeighbourOperation", op, block_hash, nil)
			if call == nil || call.Error != nil {
				delete(IM.Neighbours, a)
				IM.NumNeighbours--
			}
		}

		IM.CurrentOps[op.OpSig] = op
		if len(IM.CurrentOps) == 1 {
			for ; IM.NumNeighbours < int(IM.Settings.MinNumMinerConnections) ; {

			}
			go IM.mineOpBlock()
		}
		chain_len := IM.BlockChain.LongestChainLen
		numBlocks := -1
		for ;true; {
			if numBlocks >= 0 {
				if numBlocks == int(node_op.ValidateNum) {
					return nil
				}
				if chain_len < IM.BlockChain.LongestChainLen {
					numBlocks++
					chain_len = IM.BlockChain.LongestChainLen
					continue
				}
			}
			if chain_len < IM.BlockChain.LongestChainLen {
				chain_len = IM.BlockChain.LongestChainLen
				block := IM.BlockChain.LastBlockInChain
				for opsig, operation := range block.Ops {
					if opsig == op.OpSig && operation.IsAdd == isAdd {
						*block_hash = block.Hash
						numBlocks = 0
						break
					}
				}
			}
		}
	}
	return InvalidShapeHashError(opsig)
}

func (IM *InkMiner) PerformNeighbourOperation(operation Operation, hash *string) error {
	if op, ok := IM.CurrentOps[operation.OpSig]; ok {
		if op.IsAdd == operation.IsAdd {
			return nil
		}
	}
	IM.CurrentOps[operation.OpSig] = operation
	if len(IM.CurrentOps) == 1 {
		for ;IM.NumNeighbours < int(IM.Settings.MinNumMinerConnections); {

		}
		go IM.mineOpBlock()
	}
	return nil
}

func (IM *InkMiner) isValidOperation(operation Operation) bool {
	for _, block := range IM.BlockChain.Blocks {
		for _, op := range block.Ops {
			if !checkOverlap(operation.Op, op.Op) {
				return false
			}
		}
	}
	return true
}

func (IM *InkMiner) ValidateAndPushBlock(block Block, _pushed *bool) error {
	*_pushed = false
	if _, ok := IM.BlockChain.Blocks[block.Hash]; ok {
		return nil
	}
	if _, ok := IM.BlockChain.Blocks[block.PrevHash]; !ok {
		return ParentBlockDoesntExistError(block.PrevHash)
	}

	if block.Ops != nil {
		if checkPoW(block.Hash, int(IM.Settings.PoWDifficultyOpBlock)) {
			*_pushed = true
			IM.BlockChain.Blocks[block.Hash] = block
			if block.PrevHash == IM.BlockChain.LastBlockInChain.Hash {
				*IM.BlockChain.LastBlockInChain = block
				IM.BlockChain.LongestChainLen++
			}
			for a, c := range IM.Neighbours {
				call := c.Go("InkMiner.ValidateAndPushBlock", block, _pushed, nil)
				if call == nil || call.Error != nil {
					delete(IM.Neighbours, a)
					IM.NumNeighbours--
				}
			}
			if !IM.IsMining {
				IM.IsMining = true
				go IM.mineNoOpBlock()
			}
			return nil
		}
	}

	if checkPoW(block.Hash, int(IM.Settings.PoWDifficultyNoOpBlock)) {
		*_pushed = true
		IM.BlockChain.Blocks[block.Hash] = block
		if block.PrevHash == IM.BlockChain.LastBlockInChain.Hash {
			*IM.BlockChain.LastBlockInChain = block
			IM.BlockChain.LongestChainLen++
		}
		for a, c := range IM.Neighbours {
			call := c.Go("InkMiner.ValidateAndPushBlock", block, _pushed, nil)
			if call == nil || call.Error != nil {
				delete(IM.Neighbours, a)
				IM.NumNeighbours--
			}
		}
		if !IM.IsMining {
			IM.IsMining = true
			go IM.mineNoOpBlock()
		}
		return nil
	}

	return ProofOfWorkInvalidError(block.Hash)
}

func checkPoW(hash string, n int) bool {
	var comp string
	for i := 0; i < n; i++ {
		comp += "0"
	}
	if hash[len(hash)-n:] == comp {
		return true
	}
	return false
}

func initiateHeartbeats(key ecdsa.PublicKey, heartbeat uint32, client *rpc.Client) {
	var ignored bool
	for ;true; {
		time.Sleep(time.Duration(heartbeat/10)*time.Millisecond)
		err := client.Call("RServer.HeartBeat", key, &ignored)
		if err != nil {
			log.Fatalf("Error: %s", err)
			return
		}
	}
}

func acceptConns(listener net.Listener, server *rpc.Server) {
	for {
		conn, _ := listener.Accept()
		go server.ServeConn(conn)
	}
}

// Checks for overlap between two SVG operations
// Returns nil if error
func checkOverlap(op1 string, op2 string) bool {

	split1 := strings.Split(op1, "\"")
	shapeSvgString1 := split1[1]
	transparent1 := split1[5] == "transparent"

	split2 := strings.Split(op2, "\"")
	shapeSvgString2 := split2[1]
	transparent2 := split2[5] == "transparent"

	if transparent1 && transparent2 {
		// Both transparent, check for overlap of line segments
		i := 0
		svgCommands1 := strings.Split(shapeSvgString1, " ")

		var currX1, currY1, prevX1, prevY1, dX1, dY1 float64
		var currX1copy, currY1copy, prevX1copy, prevY1copy, dX1copy, dY1copy int
		var slope1, intercept1 float64
		fmt.Printf("%v %v %v %v %v %v",currX1copy, currY1copy, prevX1copy, prevY1copy, dX1copy, dY1copy)
		for {
			if i >= len(svgCommands1) {
				break
			}

			prevX1 = currX1
			prevY1 = currY1

			command1 := svgCommands1[i]
			i++

			if command1 == "M" {
				currX1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					currX1 = float64(currX1copy)
				}
				currY1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					currY1 = float64(currY1copy)
				}
			} else if command1 == "m" {
				dX1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					dX1 = float64(dX1copy)
				}
				dY1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					dY1 = float64(dY1copy)
				}

				currX1 += dX1
				currY1 += dY1
			} else if command1 == "L" {
				currX1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					currX1 = float64(currX1copy)
				}
				currY1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					currY1 = float64(currY1copy)
				}

				if currX1 != prevX1 {
					slope1 = (currY1-prevY1)/(currX1-prevX1)
					intercept1 = currY1 - slope1*currX1

					if checkIntercept(slope1, intercept1, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
						return true
					}
				} else if checkIntercept(0, 0, currX1, prevX1, prevY1, currY1, shapeSvgString2) {
					return true
				}
			} else if command1 == "l" {
				dX1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				dY1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					dY1 = float64(dY1copy)
					dX1 = float64(dX1copy)
				}

				currX1 += dX1
				currY1 += dY1

				if dX1 != 0 {
					slope1 = dY1/dX1
					intercept1 = currY1 - slope1*currX1

					if checkIntercept(slope1, intercept1, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
						return true
					}
				} else if checkIntercept(0, 0, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
					return true
				}
			} else if command1 == "H" {
				currX1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					currX1 = float64(currX1copy)
				}

				if checkIntercept(0, currY1, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
					return true
				}
			} else if command1 == "h" {
				dX1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					dX1 = float64(dX1copy)
				}

				currX1 += dX1

				if checkIntercept(0, currY1, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
					return true
				}
			} else if command1 == "V" {
				currY1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					currY1 = float64(currY1copy)
				}

				if checkIntercept(0, 0, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
					return true
				}
			} else if command1 == "v" {
				dY1copy, err := strconv.Atoi(svgCommands1[i])
				i++
				if err != nil {
					return false
				} else {
					dY1 = float64(dY1copy)
				}

				currY1 += dY1

				if checkIntercept(0, 0, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
					return true
				}
			} else if command1 == "Z" || command1 == "z" {
				currX1 = 0
				currY1 = 0

				if currX1 != prevX1 {
					slope1 = (currY1-prevY1)/(currX1-prevX1)
					intercept1 = currY1 - slope1*currX1

					if checkIntercept(slope1, intercept1, prevX1, currX1, prevY1, currY1, shapeSvgString2) {
						return true
					}
				} else if checkIntercept(0, 0, prevX1, currX1, prevX1, currX1, shapeSvgString2) {
					return true
				}
			} else {
				return false
			}
		}

		return false

	} else if !transparent1 {
		// 2nd shape is filled, check if any point in 1st shape is in bounds of 2nd
		return isBoundedBy(shapeSvgString1, shapeSvgString2)
	} else if !transparent2 {
		// 1st shape is filled, check if any point in 2nd shape is in bounds of 1st
		return isBoundedBy(shapeSvgString2, shapeSvgString1)
	}

	// shouldn't ever get here
	return false
}

// Given the equation of a line and an svg string, check if they intercept at any point
// Returns true if intercept or error, false otherwise
// Nil slope is a vertical line
func checkIntercept(slope, intercept float64, initX, endX float64, initY, endY float64, shapeSvgString string) bool {

	i := 0
	svgCommands := strings.Split(shapeSvgString, " ")

	var currX, currY, prevX, prevY, dX, dY float64
	var currXcopy, currYcopy, prevXcopy, prevYcopy, dXcopy, dYcopy int
	fmt.Printf("%v %v %v %v %v %v",currXcopy, currYcopy, prevXcopy, prevYcopy, dXcopy, dYcopy)
	var currSlope, currIntercept float64
	var command string
	var err error

	currX = 0
	currY = 0

	for {
		if i >= len(svgCommands) {
			break
		}

		prevX = currX
		prevY = currY
		command = svgCommands[i]
		i++

		if command == "M" {
			currXcopy, err = strconv.Atoi(svgCommands[i])
			i++
			currYcopy, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			} else {
				currX = float64(currXcopy)
				currY = float64(currYcopy)
			}
		} else if command == "m" {
			dXcopy, err = strconv.Atoi(svgCommands[i])
			i++
			dYcopy, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			} else {
				dX = float64(dXcopy)
				dY = float64(dYcopy)
			}

			currX += dX
			currY += dY
		} else {
			if command == "L" {
				currXcopy, err = strconv.Atoi(svgCommands[i])
				i++
				currYcopy, err = strconv.Atoi(svgCommands[i])
				i++
				if err != nil {
					return true
				} else {
					currX = float64(currXcopy)
					currY = float64(currYcopy)
				}

				if currX != prevX {
					currSlope = (currY-prevY)/(currX-prevX)
					currIntercept = currY - currSlope*currX
				} else {
					currSlope = 0
					currIntercept = 0
				}
			} else if command == "l" {
				dXcopy, err = strconv.Atoi(svgCommands[i])
				i++
				dYcopy, err = strconv.Atoi(svgCommands[i])
				i++
				if err != nil {
					return true
				} else {
					dX = float64(dXcopy)
					dY = float64(dYcopy)
				}

				currX += dX
				currY += dY

				if dX != 0 {
					currSlope = dY/dX
					currIntercept = currY - currSlope*currX
				} else {
					currSlope = 0
					currIntercept = 0
				}
			} else if command == "H" {
				currXcopy, err = strconv.Atoi(svgCommands[i])
				i++
				if err != nil {
					return true
				} else {
					currX = float64(currXcopy)
				}

				currSlope = 0
				currIntercept = currY
			} else if command == "h" {
				dXcopy, err = strconv.Atoi(svgCommands[i])
				i++
				if err != nil {
					return true
				} else {
					dX = float64(dXcopy)
				}

				currX += dX
				currSlope = 0
				currIntercept = currY
			} else if command == "V" {
				currYcopy, err = strconv.Atoi(svgCommands[i])
				i++
				if err != nil {
					return true
				} else {
					currY = float64(currYcopy)
				}

				currSlope = 0
				currIntercept = 0
			} else if command == "v" {
				dYcopy, err = strconv.Atoi(svgCommands[i])
				i++
				if err != nil {
					return true
				} else {
					dY = float64(dYcopy)
				}

				currY += dY
				currSlope = 0
				currIntercept = 0
			} else if command == "Z" || command == "z" {
				currX = 0
				currY = 0

				if currX != prevX {
					currSlope = (currY-prevY)/(currX-prevX)
					currIntercept = currY - currSlope*currX
				} else {
					currSlope = 0
					currIntercept = 0
				}
			} else {
				return true
			}

			// Check for intercept
			// Case 1: 2 vertical lines overlapping
			if slope == 0 && currSlope == 0 && currX == initX && ((prevY >= math.Min(initY, endY) && prevY <= math.Max(initY, endY)) || (currY >= math.Min(initY, endY) && currY <= math.Max(initY, endY))) {
				return true

				// Case 2: current line has valid slope
			} else if currSlope != 0 {
				// Parallel lines
				if slope == currSlope && ((math.Min(initX, endX) >= math.Min(prevX, currX) && math.Min(initX, endX) <= math.Max(prevX, currX)) || (math.Min(prevX, currX) >= math.Min(initX, endX) && math.Min(prevX, currX) <= math.Max(initX, endX))) {
					return true

					// Intersecting lines
				} else if slope != 0 {
					intersection := (intercept - currIntercept)/(currSlope - slope)
					if intersection >= math.Min(initX, endX) && intersection <= math.Max(initX, endX) && intersection >= math.Min(prevX, currX) && intersection <= math.Max(prevX, currX) {
						return true
					}

					// input line is vertical
				} else {
					y := currSlope*initX + currIntercept
					if initX >= math.Min(prevX, currX) && initX <= math.Max(prevX, currX) && y >= math.Min(initY, endY) && y <= math.Max(initY, endY) {
						return true
					}
				}
				// Case 3: only input line has valid slope
			} else if slope != 0 {
				y := slope*currX + intercept
				if currX >= math.Min(initX, endX) && currX <= math.Max(initX, endX) && y >= math.Min(prevY, currY) && y <= math.Max(prevY, currY) {
					return true
				}
			}
		}
	}

	return false

}

// Checks if inner SVG is bounded by the outer SVG string
// Used to check if inner string is overlapping a filled outer string
func isBoundedBy(inner, outer string) bool {
	return true
}