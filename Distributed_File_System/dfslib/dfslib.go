/*

This package specifies the application's interface to the distributed
file system (DFS) system to be used in assignment 2 of UBC CS 416
2017W2.

*/

package dfslib

import (
	"fmt"
	"os"
	"net/rpc"
	"log"
	"unicode"
	"../serverdfs"
	"os/user"
	"net"
	"strings"
)

// A Chunk is the unit of reading/writing in DFS.
type Chunk [32]byte

// Represents a type of file access.
type FileMode int

const (
	// Read mode.
	READ FileMode = iota

	// Read/Write mode.
	WRITE

	// Disconnected read mode.
	DREAD
)

////////////////////////////////////////////////////////////////////////////////////////////
// <ERROR DEFINITIONS>

// These type definitions allow the application to explicitly check
// for the kind of error that occurred. Each API call below lists the
// errors that it is allowed to raise.
//
// Also see:
// https://blog.golang.org/error-handling-and-go
// https://blog.golang.org/errors-are-values

// Contains serverAddr
type DisconnectedError string

func (e DisconnectedError) Error() string {
	return fmt.Sprintf("DFS: Not connnected to server [%s]", string(e))
}

// Contains chunkNum that is unavailable
type ChunkUnavailableError uint8

func (e ChunkUnavailableError) Error() string {
	return fmt.Sprintf("DFS: Latest verson of chunk [%d] unavailable", e)
}

// Contains filename
type OpenWriteConflictError string

func (e OpenWriteConflictError) Error() string {
	return fmt.Sprintf("DFS: Filename [%s] is opened for writing by another client", string(e))
}

// Contains file mode that is bad.
type BadFileModeError FileMode

func (e BadFileModeError) Error() string {
	return fmt.Sprintf("DFS: Cannot perform this operation in current file mode [%s]", string(e))
}

// Contains filename.
type WriteModeTimeoutError string

func (e WriteModeTimeoutError) Error() string {
	return fmt.Sprintf("DFS: Write access to filename [%s] has timed out; reopen the file", string(e))
}

// Contains filename
type BadFilenameError string

func (e BadFilenameError) Error() string {
	return fmt.Sprintf("DFS: Filename [%s] includes illegal characters or has the wrong length", string(e))
}

// Contains filename
type FileUnavailableError string

func (e FileUnavailableError) Error() string {
	return fmt.Sprintf("DFS: Filename [%s] is unavailable", string(e))
}

// Contains local path
type LocalPathError string

func (e LocalPathError) Error() string {
	return fmt.Sprintf("DFS: Cannot access local path [%s]", string(e))
}

// Contains filename
type FileDoesNotExistError string

func (e FileDoesNotExistError) Error() string {
	return fmt.Sprintf("DFS: Cannot open file [%s] in D mode as it does not exist locally", string(e))
}

// </ERROR DEFINITIONS>
////////////////////////////////////////////////////////////////////////////////////////////

// Represents a file in the DFS system.
type DFSFile interface {
	// Reads chunk number chunkNum into storage pointed to by
	// chunk. Returns a non-nil error if the read was unsuccessful.
	//
	// Can return the following errors:
	// - DisconnectedError (in READ,WRITE modes)
	// - ChunkUnavailableError (in READ,WRITE modes)
	Read(chunkNum uint8, chunk *Chunk) (err error)

	// Writes chunk number chunkNum from storage pointed to by
	// chunk. Returns a non-nil error if the write was unsuccessful.
	//
	// Can return the following errors:
	// - BadFileModeError (in READ,DREAD modes)
	// - DisconnectedError (in WRITE mode)
	// - WriteModeTimeoutError (in WRITE mode)
	Write(chunkNum uint8, chunk *Chunk) (err error)

	// Closes the file/cleans up. Can return the following errors:
	// - DisconnectedError
	Close() (err error)
}

type DfsFile struct {
	Fp *os.File
	Mode FileMode
	Fm serverdfs.FMetaData
	Dfs *Dfs
	IsOpen bool
}

func (DfsF *DfsFile) Read(chunkNum uint8, chunk *Chunk) error {
	if chunkNum > 255 {
		return ChunkUnavailableError(chunkNum)
	}
	if DfsF.Fp != nil || DfsF.Mode == DREAD {
		if !DfsF.IsOpen {
			var err error
			DfsF.Fp, err = os.Open(DfsF.Fm.Fid.Name+".dfs")
			if err != nil {
				return err
			}
		}
		b := make([]byte, 32)
		DfsF.Fp.ReadAt(b, int64(chunkNum*32))
		copy(chunk[:], b)
		fmt.Printf("%s %d\n", *chunk, chunkNum)
		return nil
	}

	cd := serverdfs.ChunkData{chunkNum, *chunk, &DfsF.Fm}
	var read [32]byte
	err := DfsF.Dfs.RpcCli.Call("DFSServer.ReadFile", cd, &read)
	if err != nil {
		if err.Error()[0:4] == "open" {
			return ChunkUnavailableError(chunkNum)
		}
		return DisconnectedError(DfsF.Dfs.ServerAddr)
	}
	*chunk = read
	return nil
}

func (DfsF *DfsFile) Write(chunkNum uint8, chunk *Chunk) error {
	if DfsF.Mode != WRITE {
		return BadFileModeError(DfsF.Mode)
	}
	if DfsF.Fp != nil {
		if !DfsF.IsOpen {
			DfsF.Fp, _ = os.Create(DfsF.Fm.Fid.Name + ".dfs")
			DfsF.IsOpen = true
		}
		b := make([]byte, 32)
		copy(b, chunk[:])
		DfsF.Fp.WriteAt(b, int64(chunkNum*32))
		DfsF.Fp.Sync()
		return nil
	}
	cd := serverdfs.ChunkData{chunkNum, *chunk, &DfsF.Fm}
	var write [32]byte
	err := DfsF.Dfs.RpcCli.Call("DFSServer.WriteFile", cd, &write)
	if err != nil {
		return DisconnectedError(DfsF.Dfs.ServerAddr)
	}
	*chunk = write
	return nil
}

func (DfsF *DfsFile) Close() error {
	if DfsF.Fp != nil {
		DfsF.Fp.Close()
		var closed bool
		err := DfsF.Dfs.RpcCli.Call("DFSServer.CloseFile", DfsF.Fm, &closed)
		if err != nil {
			return DisconnectedError(DfsF.Dfs.ServerAddr)
		}
		DfsF.IsOpen = false
	}
	return nil
}

// Represents a connection to the DFS system.
type DFS interface {
	// Check if a file with filename fname exists locally (i.e.,
	// available for DREAD reads).
	//
	// Can return the following errors:
	// - BadFilenameError (if filename contains non alpha-numeric chars or is not 1-16 chars long)
	LocalFileExists(fname string) (exists bool, err error)

	// Check if a file with filename fname exists globally.
	//
	// Can return the following errors:
	// - BadFilenameError (if filename contains non alpha-numeric chars or is not 1-16 chars long)
	// - DisconnectedError
	GlobalFileExists(fname string) (exists bool, err error)

	// Opens a filename with name fname using mode. Creates the file
	// in READ/WRITE modes if it does not exist. Returns a handle to
	// the file through which other operations on this file can be
	// made.
	//
	// Can return the following errors:
	// - OpenWriteConflictError (in WRITE mode)
	// - DisconnectedError (in READ,WRITE modes)
	// - FileUnavailableError (in READ,WRITE modes)
	// - FileDoesNotExistError (in DREAD mode)
	// - BadFilenameError (if filename contains non alpha-numeric chars or is not 1-16 chars long)
	Open(fname string, mode FileMode) (f DFSFile, err error)

	// Disconnects from the server. Can return the following errors:
	// - DisconnectedError
	UMountDFS() (err error)
}

type Dfs struct {
	ServerAddr string
	LocalIP string
	Path string
	RpcCli *rpc.Client
	RpcServ *rpc.Server
	Cli *serverdfs.Client
	CliFiles map[string]*DfsFile
}

func (dfs *Dfs) LocalFileExists(fname string) (bool, error) {
	if !isValidFileName(fname) {
		return false, BadFilenameError(fname)
	}

	for name := range dfs.CliFiles {
		if name == fname {
			return true, nil
		}
	}
	return false, nil
}

func (dfs *Dfs) GlobalFileExists(fname string) (bool, error) {
	if !isValidFileName(fname) {
		return false, BadFilenameError(fname)
	}

	if dfs.RpcCli == nil {
		return false, DisconnectedError(dfs.ServerAddr)
	}

	exists, err := dfs.LocalFileExists(fname)
	if exists {
		return true, nil
	}

	fd := serverdfs.FileID{fname, ""}
	err = dfs.RpcCli.Call("DFSServer.ExistsFile", fd, &exists)
	if err != nil {
		return false, DisconnectedError(dfs.ServerAddr)
	}
	return exists, nil
}

func (dfs *Dfs) Open(fname string, mode FileMode) (DFSFile, error) {
	if !isValidFileName(fname) {
		return nil, BadFilenameError(fname)
	}

	if mode != DREAD {
		fid := serverdfs.FileID{fname, dfs.Cli.Id}
		fm := new(serverdfs.FMetaData)
		err := dfs.RpcCli.Call("DFSServer.OpenFile", fid, fm)
		if err != nil {
			return nil, FileUnavailableError(fname)
		}

		if mode == WRITE && fm.IsWrite {
			return nil, OpenWriteConflictError(fname)
		}
		if fm.Fid.AuthorId == dfs.Cli.Id {
			exists, _ := dfs.LocalFileExists(fname)
			var fp *os.File

			if !exists {
				fp, err = os.Create(fname + ".dfs")
				if err != nil {
					fmt.Println(os.Getwd())
					return nil, err
				}
				fp.Truncate(256 * 32)
			}
			if exists {
				fp, err = os.Open(fname + ".dfs")
				if err != nil {
					return nil, err
				}
			}
			dfsf := &DfsFile{fp, mode, *fm, dfs, true}
			dfs.CliFiles[fname] = dfsf
			registerFileOnSocket(dfsf, dfs.RpcServ)
			return dfsf, nil
		}
		return &DfsFile{nil, mode, *fm, dfs, true}, nil
	}
	exists, _ := dfs.LocalFileExists(fname)
	if !exists {
		return nil, FileDoesNotExistError(fname)
	}
	return dfs.CliFiles[fname], nil
}

func (dfs *Dfs) UMountDFS() error {
	if dfs.RpcCli == nil {
		return DisconnectedError(dfs.ServerAddr)
	}
	var dis bool
	err := dfs.RpcCli.Call("DFSServer.DisconnectClient", &dfs.Cli, &dis)
	if err != nil {
		return DisconnectedError(dfs.ServerAddr)
	}
	err = dfs.RpcCli.Close()
	if err != nil {
		return DisconnectedError(dfs.ServerAddr)
	}
	go dfs.closeFiles()
	return nil
}

func (dfs *Dfs) closeFiles() {
	for _, file := range dfs.CliFiles {
		if file.IsOpen {
			file.IsOpen = false
			file.Fp.Close()
		}
	}
}

// The constructor for a new DFS object instance. Takes the server's
// IP:port address string as parameter, the localIP to use to
// establish the connection to the server, and a localPath path on the
// local filesystem where the client has allocated storage (and
// possibly existing state) for this DFS.
//
// The returned dfs instance is singleton: an application is expected
// to interact with just one dfs at a time.
//
// This call should succeed regardless of whether the server is
// reachable. Otherwise, applications cannot access (local) files
// while disconnected.
//
// Can return the following errors:
// - LocalPathError
// - Networking errors related to localIP or serverAddr
func MountDFS(serverAddr string, localIP string, localPath string) (dfs DFS, err error) {
	d := Dfs{
		serverAddr,
		localIP,
		localPath,
		nil,
		nil,
		new(serverdfs.Client),
		make(map[string]*DfsFile)}
	client, err := rpc.Dial("tcp", serverAddr)
	if err != nil {
		return &d, nil
	}

	var exists bool
	u, _ := user.Current()
	id := u.Username+localPath
	cli := &serverdfs.Client{id, localIP, "", true, make([]*serverdfs.FMetaData, 0)}

	err = client.Call("DFSServer.ExistsClient", cli, &exists)
	if err != nil {
		return nil, DisconnectedError(serverAddr)
	}

	d.RpcCli = client
	localPort, cliServ := MountClientSocket(&d)
	cli.Port = localPort
	d.Cli = cli
	d.RpcServ = cliServ

	if exists {
		var repl bool
		err = client.Call("DFSServer.ReplaceClient", cli, &repl)
		if err != nil {
			return nil, DisconnectedError(serverAddr)
		}
	}

	if !exists {
		err = client.Call("DFSServer.RegisterClient", cli, &id)
		if err != nil {
			return nil, DisconnectedError(serverAddr)
		}
	}

	wd, _ := os.Getwd()
	err = os.MkdirAll(wd+localPath, os.ModePerm)
	if err != nil {
		return nil, LocalPathError(localPath)
	}
	err = os.Chdir(wd+localPath)
	if err != nil {
		return nil, LocalPathError(localPath)
	}
	return &d, nil
}


func MountClientSocket(dfs *Dfs) (s string, cliServ *rpc.Server) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("%v \n", err)
	}
	s = strings.TrimPrefix(l.Addr().String(), "[::]")
	cliServ = rpc.NewServer()
	go cliServ.Accept(l)
	return s, cliServ
}

func registerFileOnSocket(f *DfsFile, cliServ *rpc.Server) {
	cliServ.RegisterName(f.Fm.Fid.Name, f)
}

func isValidFileName(fname string) bool {
	if len(fname) < 1 || len(fname) > 16 {
		return false
	}

	for _, s := range fname {
		if !unicode.IsLetter(s) && !unicode.IsNumber(s) {
			return false
		}
	}
	return true
}

func getFilename(dfsf *DfsFile) string {
	dfs := dfsf.Dfs
	for fname := range dfs.CliFiles {
		if dfs.CliFiles[fname] == dfsf {
			return fname
		}
	}
	return ""
}