/*

This package specifies the application's interface to the the BlockArt
library (blockartlib) to be used in project 1 of UBC CS 416 2017W2.

*/

package blockartlib

import "crypto/ecdsa"
import "fmt"
import "net"
import "strings"
import "strconv"
import "math"
import "net/rpc"
import "math/big"
import "crypto/rand"


// Represents a type of shape in the BlockArt system.
type ShapeType int

const (
	// Path shape.
	PATH ShapeType = iota

	// Circle shape (extra credit).
	// CIRCLE
)

// Settings for a canvas in BlockArt.
type CanvasSettings struct {
	// Canvas dimensions
	CanvasXMax uint32
	CanvasYMax uint32
}

// Settings for an instance of the BlockArt project/network.
type MinerNetSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string

	// The minimum number of ink miners that an ink miner should be
	// connected to. If the ink miner dips below this number, then
	// they have to retrieve more nodes from the server using
	// GetNodes().
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

type CanvasInstance struct {
	client *rpc.Client
	minerAddr string
	privKey ecdsa.PrivateKey
	CanvasSettings CanvasSettings
}

type ArtNodeHash struct {
	R, S *big.Int
}

type Operation struct {
	Op string
	OpSig string
	NodeKey ecdsa.PublicKey
	Ink uint32
	IsAdd bool
}

type SignedNodeHash struct {
	R, S *big.Int
}

type NodeOp struct {
	Op string
	OpSig string
	ValidateNum uint8
	InkRequired uint32
}

type Block struct {
	PrevHash string
	Ops map[string]Operation
	MinerKey ecdsa.PublicKey
	Nonce uint32
	Hash string
	BlockNumInChain int
}

////////////////////////////////////////////////////////////////////////////////////////////
// <ERROR DEFINITIONS>

// These type definitions allow the application to explicitly check
// for the kind of error that occurred. Each API call below lists the
// errors that it is allowed to raise.
//
// Also see:
// https://blog.golang.org/error-handling-and-go
// https://blog.golang.org/errors-are-values

// Contains address IP:port that art node cannot connect to.
type DisconnectedError string

func (e DisconnectedError) Error() string {
	return fmt.Sprintf("BlockArt: cannot connect to [%s]", string(e))
}

// Contains amount of ink remaining.
type InsufficientInkError uint32

func (e InsufficientInkError) Error() string {
	return fmt.Sprintf("BlockArt: Not enough ink to addShape [%d]", uint32(e))
}

// Contains the offending svg string.
type InvalidShapeSvgStringError string

func (e InvalidShapeSvgStringError) Error() string {
	return fmt.Sprintf("BlockArt: Bad shape svg string [%s]", string(e))
}

// Contains the offending svg string.
type ShapeSvgStringTooLongError string

func (e ShapeSvgStringTooLongError) Error() string {
	return fmt.Sprintf("BlockArt: Shape svg string too long [%s]", string(e))
}

// Contains the bad shape hash string.
type InvalidShapeHashError string

func (e InvalidShapeHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid shape hash [%s]", string(e))
}

// Contains the bad shape hash string.
type ShapeOwnerError string

func (e ShapeOwnerError) Error() string {
	return fmt.Sprintf("BlockArt: Shape owned by someone else [%s]", string(e))
}

// Empty
type OutOfBoundsError struct{}

func (e OutOfBoundsError) Error() string {
	return fmt.Sprintf("BlockArt: Shape is outside the bounds of the canvas")
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

// </ERROR DEFINITIONS>
////////////////////////////////////////////////////////////////////////////////////////////

// Represents a canvas in the system.
type Canvas interface {
	// Adds a new shape to the canvas.
	// Can return the following errors:
	// - DisconnectedError
	// - InsufficientInkError
	// - InvalidShapeSvgStringError
	// - ShapeSvgStringTooLongError
	// - ShapeOverlapError
	// - OutOfBoundsError
	AddShape(validateNum uint8, shapeType ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error)

	// Returns the encoding of the shape as an svg string.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidShapeHashError
	GetSvgString(shapeHash string) (svgString string, err error)

	// Returns the amount of ink currently available.
	// Can return the following errors:
	// - DisconnectedError
	GetInk() (inkRemaining uint32, err error)

	// Removes a shape from the canvas.
	// Can return the following errors:
	// - DisconnectedError
	// - ShapeOwnerError
	DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error)

	// Retrieves hashes contained by a specific block.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidBlockHashError
	GetShapes(blockHash string) (shapeHashes []string, err error)

	// Returns the block hash of the genesis block.
	// Can return the following errors:
	// - DisconnectedError
	GetGenesisBlock() (blockHash string, err error)

	// Retrieves the children blocks of the block identified by blockHash.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidBlockHashError
	GetChildren(blockHash string) (blockHashes []string, err error)

	// Closes the canvas/connection to the BlockArt network.
	// - DisconnectedError
	CloseCanvas() (inkRemaining uint32, err error)
}

var canvasInstance *CanvasInstance

// The constructor for a new Canvas object instance. Takes the miner's
// IP:port address string and a public-private key pair (ecdsa private
// key type contains the public key). Returns a Canvas instance that
// can be used for all future interactions with blockartlib.
//
// The returned Canvas instance is a singleton: an application is
// expected to interact with just one Canvas instance at a time.
//
// Can return the following errors:
// - DisconnectedError
func OpenCanvas(minerAddr string, privKey ecdsa.PrivateKey) (canvas Canvas, setting CanvasSettings, err error) {

	if canvasInstance != nil {
		return canvasInstance, canvasInstance.CanvasSettings, nil
	}

	conn, err := net.Dial("tcp", minerAddr)
	if err != nil {
		return nil, CanvasSettings{}, DisconnectedError(minerAddr)
	}

	canvasInstance := &CanvasInstance{client: rpc.NewClient(conn), minerAddr: minerAddr, privKey: privKey}
	msg := []byte("Initiate Art Node")
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, msg)
	// var setting CanvasSettings
	err = canvasInstance.client.Call("InkMiner.VerifyArtNode", ArtNodeHash{R: r, S: s}, &setting)

	if err != nil {
		return nil, CanvasSettings{}, DisconnectedError(minerAddr)
	} else {
		canvasInstance.CanvasSettings = setting
		return canvasInstance, setting, nil
	}

}

func (canvas *CanvasInstance) CloseCanvas() (inkRemaining uint32, err error) {

	canvasInstance = nil
	return canvas.GetInk()

}

func (canvas *CanvasInstance) AddShape(validateNum uint8, shapeType ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error) {

	if len([]rune(shapeSvgString)) > 128 {
		return "", "", 0, ShapeSvgStringTooLongError(shapeSvgString)
	}

	currentInk, err := canvas.GetInk()
	if err != nil {
		return "", "", 0, err
	}

	// if fill == nil || fill == "" {
	// 	return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
	// }

	// if stroke == nil || stroke == "" {
	// 	return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
	// }

	if !isInBounds(shapeSvgString, canvas.CanvasSettings.CanvasXMax, canvas.CanvasSettings.CanvasYMax) {
		return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
	}

	isTransparentFill := fill == "transparent"
	isTransparentStroke := stroke == "transparent"

	if isTransparentFill && isTransparentStroke {
		return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
	}

	if !isTransparentFill {
		if !isEnclosedShape(shapeSvgString) {
			return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
		}

		if isSelfIntersecting(shapeSvgString) {
			return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
		}
	}

	inkUsed := calculateInkUsed(shapeSvgString, !isTransparentFill, !isTransparentStroke)
	if inkUsed == 0 {
		return "", "", currentInk, InvalidShapeSvgStringError(shapeSvgString)
	}

	if inkUsed > currentInk {
		return "", "", currentInk, InsufficientInkError(currentInk)
	} else {
		// Call good, send to miner
		var blockHash string
		op := "<path d=\"" + shapeSvgString + "\" stroke=\"" + stroke + "\" fill=\"" + fill + "\"/>"
		r, s, err := ecdsa.Sign(rand.Reader, &canvas.privKey, []byte(op))
		shapeHash := r.String() + s.String()
		err = canvas.client.Call("InkMiner.PerformOperation", NodeOp{Op: op, OpSig: shapeHash, ValidateNum: validateNum, InkRequired: inkUsed}, &blockHash)

		// TODO: Check if get error in response instead of just reporting a failure to connect
		if err != nil {
			return "", "", 0, err
		}

		currentInk, err = canvas.GetInk()
		if err != nil {
			return "", "", 0, err
		}

		return shapeHash, blockHash, inkRemaining, nil
	}
}

func (canvas *CanvasInstance) GetSvgString(shapeHash string) (svgString string, err error) {

	var op Operation
	err = canvas.client.Call("InkMiner.GetSvgString", shapeHash, &op)
	if err != nil {
		// TODO: better error handling?
		return "", err
	}

	return op.Op, nil

}

func (canvas *CanvasInstance) GetInk() (inkRemaining uint32, err error) {

	// var inkRemaining uint32
	err = canvas.client.Call("InkMiner.GetInk", canvas.privKey.Public(), &inkRemaining)
	if err != nil {
		return 0, DisconnectedError(canvas.minerAddr)
	} else {
		return inkRemaining, nil
	}

}

func (canvas *CanvasInstance) DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error) {

	var blockHash string
	err = canvas.client.Call("InkMiner.PerformOperation", NodeOp{Op: "", OpSig: shapeHash, ValidateNum: validateNum, InkRequired: 0}, &blockHash)
	if err != nil {
		return 0, err
	}

	return canvas.GetInk()

}

func (canvas *CanvasInstance) GetShapes(blockHash string) (shapeHashes []string, err error) {

	var shapeOps []Operation
	err = canvas.client.Call("InkMiner.GetShapes", blockHash, &shapeOps)
	if err != nil {
		return nil, err
	}

	// var shapeHashes [len(shapeOps)]string

	for i := 0; i < len(shapeHashes); i++ {
		shapeHashes[i] = shapeOps[i].OpSig
	}

	return shapeHashes, nil

}

func (canvas *CanvasInstance) GetGenesisBlock() (blockHash string, err error) {

	// var blockHash string
	err = canvas.client.Call("InkMiner.GetGenesisBlock", canvas.privKey.Public(), &blockHash)
	if err != nil {
		return "", DisconnectedError(canvas.minerAddr)
	}
	
	return blockHash, nil

}

func (canvas *CanvasInstance) GetChildren(blockHash string) (blockHashes []string, err error) {

	var children []Block
	err = canvas.client.Call("InkMiner.GetChildren", blockHash, &children)
	if err != nil {
		return nil, err
	}

	// var blockHashes [len(children)]string

	for i := 0; i < len(blockHashes); i++ {
		blockHashes[i] = children[i].Hash
	}

	return blockHashes, nil

}

func isInBounds(shapeSvgString string, xMax uint32, yMax uint32) bool {

	index := 0
	svgCommands := strings.Split(shapeSvgString, " ")
	command := svgCommands[index]
	index++
	if command != "M" {
		return false
	}

	var currX, initX, currY, initY, dX, dY int

	initX, err := strconv.Atoi(svgCommands[index])
	index++
	initY, err = strconv.Atoi(svgCommands[index])
	index++
	if err != nil {
		return false
	}

	currX = initX
	currY = initY

	for {
		if index >= len(svgCommands) {
			return true
		}

		command = svgCommands[index]
		index++

		if command == "M" {
			currX, err = strconv.Atoi(svgCommands[index])
			index++
			currY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "m" {
			dX, err = strconv.Atoi(svgCommands[index])
			index++
			dY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currX += dX
			currY += dY
		} else if command == "L" {
			currX, err = strconv.Atoi(svgCommands[index])
			index++
			currY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "l" {
			dX, err = strconv.Atoi(svgCommands[index])
			index++
			dY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currX += dX
			currY += dY
		} else if command == "H" {
			currX, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "h" {
			dX, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currX += dX
		} else if command == "V" {
			currY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "v" {
			dY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currY += dY
		} else if command == "Z" || command == "z" {
			currX = 0
			currY = 0
		} else {
			return false
		}

		if uint32(currX) > xMax || uint32(currX) < 0 || uint32(currY) > yMax || uint32(currY) < 0 {
			return false
		}
	}
}

func isEnclosedShape(shapeSvgString string) bool {

	index := 0
	svgCommands := strings.Split(shapeSvgString, " ")
	command := svgCommands[index]
	index++
	if command != "M" {
		return false
	}

	initX, err := strconv.Atoi(svgCommands[index])
	index++
	initY, err := strconv.Atoi(svgCommands[index])
	index++
	if err != nil {
		return false
	}

	currX := initX
	currY := initY
	var dX, dY int

	for {
		if index >= len(svgCommands) {
			return false
		}

		command = svgCommands[index]
		index++

		if command == "M" || command == "m" {
			return false
		} else if command == "L" {
			currX, err = strconv.Atoi(svgCommands[index])
			index++
			currY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "l" {
			dX, err = strconv.Atoi(svgCommands[index])
			index++
			dY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currX += dX
			currY += dY
		} else if command == "H" {
			currX, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "h" {
			dX, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currX += dX
		} else if command == "V" {
			currY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}
		} else if command == "v" {
			dY, err = strconv.Atoi(svgCommands[index])
			index++
			if err != nil {
				return false
			}

			currY += dY
		} else if command == "Z" || command == "z" {
			currX = 0
			currY = 0
		} else {
			return false
		}
	}
}

func isSelfIntersecting(shapeSvgString string) bool {

	var i, j int
	i = 0

	svgCommands := strings.Split(shapeSvgString, " ")
	command := svgCommands[i]
	i++
	if command != "M" {
		return true
	}

	initX, err := strconv.Atoi(svgCommands[i])
	i++
	initY, err := strconv.Atoi(svgCommands[i])
	i++
	if err != nil {
		return true
	}

	currX := initX
	currY := initY
	var prevX, prevY, dX, dY int
	var slope, intercept int

	var command2 string
	var currX2, currY2, prevX2, prevY2, dX2, dY2 int
	var slope2, intercept2 int

	for {
		if i >= len(svgCommands) {
			break
		}

		prevX = currX
		prevY = currY
		command = svgCommands[i]
		i++

		// Set the slope and intercept for the line to be examined (nil for vertical lines)
		if command == "M" || command == "m" {
			return true
		} else if command == "L" {
			currX, err = strconv.Atoi(svgCommands[i])
			i++
			currY, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			}

			if currX != prevX {
				slope = (currY-prevY)/(currX-prevX)
				intercept = currY - slope*currX
			} else if currY == prevY {
				return true
			}
		} else if command == "l" {
			dX, err = strconv.Atoi(svgCommands[i])
			i++
			dY, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			}

			currX += dX
			currY += dY

			if dX != 0 {
				slope = dY/dX
				intercept = currY - slope*currX
			} else if dY == 0 {
				return true
			}
		} else if command == "H" {
			currX, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			}

			if currX != prevX {
				slope = 0
				intercept = currY
			} else {
				return true
			}
		} else if command == "h" {
			dX, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			}

			currX += dX

			if dX != 0 {
				slope = 0
				intercept = currY
			} else {
				return true
			}
		} else if command == "V" {
			currY, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			}

			if currY != prevY {
				slope = nil
				intercept = nil
			} else {
				return true
			}
		} else if command == "v" {
			dY, err = strconv.Atoi(svgCommands[i])
			i++
			if err != nil {
				return true
			}

			currY += dY

			if dY != 0 {
				slope = nil
				intercept = nil
			} else {
				return true
			}
		} else if command == "Z" || command == "z" {
			currX = 0
			currY = 0

			if currX != prevX {
				slope = (currY-prevY)/(currX-prevX)
				intercept = currY - slope*currX
			} else if currY == prevY {
				return true
			}
		} else {
			return true
		}

		j = i
		currX2 = currX
		currY2 = currY

		// Examine each subsequent line segment for interception
		for {
			if j >= len(svgCommands) {
				break
			}

			prevX2 = currX2
			prevY2 = currY2
			command = svgCommands[i]
			j++

			// Set the slope and intercept for the line to be examined (nil for vertical lines)
			if command == "M" || command == "m" {
				return true
			} else if command == "L" {
				currX2, err = strconv.Atoi(svgCommands[j])
				j++
				currY2, err = strconv.Atoi(svgCommands[j])
				j++
				if err != nil {
					return true
				}

				if currX2 != prevX2 {
					slope2 = (currY2-prevY2)/(currX2-prevX2)
					intercept2 = currY2 - slope2*currX2
				} else if currY2 == prevY2 {
					return true
				}
			} else if command == "l" {
				dX2, err = strconv.Atoi(svgCommands[j])
				j++
				dY2, err = strconv.Atoi(svgCommands[j])
				j++
				if err != nil {
					return true
				}

				currX2 += dX2
				currY2 += dY2

				if dX2 != 0 {
					slope2 = dY2/dX2
					intercept2 = currY2 - slope2*currX2
				} else if dY2 == 0 {
					return true
				}
			} else if command == "H" {
				currX2, err = strconv.Atoi(svgCommands[i])
				j++
				if err != nil {
					return true
				}

				if currX2 != prevX2 {
					slope2 = 0
					intercept2 = currY2
				} else {
					return true
				}
			} else if command == "h" {
				dX2, err = strconv.Atoi(svgCommands[j])
				j++
				if err != nil {
					return true
				}

				currX2 += dX2

				if dX2 != 0 {
					slope2 = 0
					intercept2 = currY2
				} else {
					return true
				}
			} else if command == "V" {
				currY2, err = strconv.Atoi(svgCommands[j])
				j++
				if err != nil {
					return true
				}

				if currY2 != prevY2 {
					slope2 = nil
					intercept2 = nil
				} else {
					return true
				}
			} else if command == "v" {
				dY2, err = strconv.Atoi(svgCommands[j])
				j++
				if err != nil {
					return true
				}

				currY2 += dY2

				if dY2 != 0 {
					slope2 = nil
					intercept2 = nil
				} else {
					return true
				}
			} else if command == "Z" || command == "z" {
				currX2 = 0
				currY2 = 0

				if currX2 != prevX2 {
					slope2 = (currY2-prevY2)/(currX2-prevX2)
					intercept2 = currY2 - slope2*currX2
				} else if currY2 == prevY2 {
					return true
				}
			} else {
				return nil
			}

			// Check for intercept
			// Case 1: 2 vertical lines overlapping
			if slope == nil && slope2 == nil && currX == currX2 && ((prevY >= math.Min(prevY2, currY2) && prevY <= math.Max(prevY2, currY2)) || (currY >= math.Min(prevY2, currY2) && currY <= math.Max(prevY2, currY2))) {
				return true
			} else if slope != nil {
				// Parallel lines
				if slope2 == slope && ((math.Min(currX2, prevX2) >= math.Min(prevX, currX) && math.Min(currX2, prevX2) <= math.Max(prevX, currX)) || (math.Min(prevX, currX) >= math.Min(currX2, prevX2) && math.Min(prevX, currX) <= math.Max(currX2, prevX2))) {
					return true

				// Intersecting lines
				} else if slope2 != nil {
					intersection := (intercept2 - intercept)/(slope - slope2)
					if intersection >= math.Min(currX2, prevX2) && intersection <= math.Max(currX2, prevX2) && intersection >= math.Min(prevX, currX) && intersection <= math.Max(prevX, currX) {
						return true
					}

				// input line is vertical
				} else {
					y := slope*prevX2 + intercept
					if prevX2 >= math.Min(prevX, currX) && prevX2 <= math.Max(prevX, currX) && y >= math.Min(currY2, prevY2) && y <= math.Max(currY2, prevY2) {
						return true
					}
				}
			// Case 3: only input line has valid slope
			} else if slope2 != nil {
				y := slope2*currX + intercept2
				if currX >= math.Min(currX2, prevX2) && currX <= math.Max(currX2, prevX2) && y >= math.Min(prevY, currY) && y <= math.Max(prevY, currY) {
					return true
				}
			}

			// No intersection, proceed to next execution of the loop
		}
	}

	return false
}

func calculateInkUsed(shapeSvgString string, fill bool, stroke bool) uint32 {

	length := 0
	area := 0

	index := 0
	svgCommands := strings.Split(shapeSvgString, " ")
	command := svgCommands[index]
	index++
	if command != "M" {
		return nil
	}

	initX, err := strconv.Atoi(svgCommands[index])
	index++
	initY, err := strconv.Atoi(svgCommands[index])
	index++
	if err != nil {
		return nil
	}

	currX := initX
	currY := initY

	var prevX, prevY, dX, dY uint32
	var slope, intercept float32

	// Calculate the fill area
	if fill {
		for {
			if index >= len(svgCommands) {
				break
			}

			prevX = currX
			prevY = currY
			command = svgCommands[index]
			index++

			if command == "M" || command == "m" {
				return nil
			} else if command == "L" {
				currX, err = strconv.Atoi(svgCommands[index])
				index++
				currY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				if currX != prevX {
					slope = (currY-prevY)/(currX-prevX)
					intercept = currY - slope*currX
					area += (slope*currX^2 + intercept*currX) - (slope*prevX^2 + intercept*prevX)
				}
			} else if command == "l" {
				dX, err = strconv.Atoi(svgCommands[index])
				index++
				dY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currX += dX
				currY += dY

				if dX != 0 {
					slope = dY/dX
					intercept = currY - slope*currX
					area += (slope*currX^2 + intercept*currX) - (slope*prevX^2 + intercept*prevX)
				}
			} else if command == "H" {
				currX, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				if currX != prevX {
					area += currY*currX - currY*prevX
				}
			} else if command == "h" {
				dX, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currX += dX

				if dX != 0 {
					area += currY*dX
				}
			} else if command == "V" {
				currY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}
			} else if command == "v" {
				dY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currY += dY
			} else if command == "Z" || command == "z" {
				currX = 0
				currY = 0

				if currX != prevX {
					slope = (currY-prevY)/(currX-prevX)
					intercept = currY - slope*currX
					area += (slope*currX^2 + intercept*currX) - (slope*prevX^2 + intercept*prevX)
				}
			} else {
				return nil
			}
		}
	}

	index = 3
	currX = initX
	currY = initY

	// Calculate the stroke length
	if stroke {
		for {
			if index >= len(svgCommands) {
				break
			}

			prevX = currX
			prevY = currY
			command = svgCommands[index]
			index++

			if command == "M" {
				currX, err = strconv.Atoi(svgCommands[index])
				index++
				currY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}
			} else if command == "m" {
				dX, err = strconv.Atoi(svgCommands[index])
				index++
				dY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currX += dX
				currY += dY
			} else if command == "L" {
				currX, err = strconv.Atoi(svgCommands[index])
				index++
				currY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				length += math.Sqrt((currX-prevX)^2 + (currY-prevY)^2)
			} else if command == "l" {
				dX, err = strconv.Atoi(svgCommands[index])
				index++
				dY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currX += dX
				currY += dY

				length += math.Sqrt(dX^2 + dY^2)
			} else if command == "H" {
				currX, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				length += math.Abs(currX-prevX)
			} else if command == "h" {
				dX, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currX += dX
				length += dX
			} else if command == "V" {
				currY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				length += math.Abs(currY-prevY)
			} else if command == "v" {
				dY, err = strconv.Atoi(svgCommands[index])
				index++
				if err != nil {
					return nil
				}

				currY += dY
				length += dY
			} else if command == "Z" || command == "z" {
				currX = 0
				currY = 0
				length += math.Sqrt((currX-prevX)^2 + (currY-prevY)^2)
			} else {
				return nil
			}
		}
	}

	area = math.Abs(area)

	// Round result up before returning
	remainder := (length + area) % 1
	if remainder > 0 {
		return length + area + (1 - remainder)
	} else {
		return length + area
	}
}
