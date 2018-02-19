// CPSC 416 | 2017W2 | Assignment 2
//
// This tests a simple, single client DFS scenario. Two clients (A and B) connect
// to the same server in turns:
//
// - Client A mounts DFS at a certain local path (see main function)
// - Client A tries to create a file with an invalid name -- this should return an error
// - Client A creates a new file for writing
// - Client A writes some content on an arbitrary chunk
// - Client A reads back the information just written
// - Client A closes the file and umounts
// - Client B later connects to the same server, but wiht a different local path
// - Client B attempts to check if the file created by Client A exists globally -- this should be true
// - Client B tries to open that file, but it fails -- client A is no longer connected.
//
// Usage:
//
// $ ./single_client [server-address]

package main

import (
	"./dfslib"

	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const (
	CHUNKNUM          = 3                           // which chunk client A will try to read from and write to
	VALID_FILE_NAME   = "cpsc416"                   // a file name client A will create
	INVALID_FILE_NAME = "invalid file;"             // a file name that the dfslib rejects
	DEADLINE          = "2018-01-29T23:59:59-08:00" // project deadline :-)
)

//////////////////////////////////////////////////////////////////////
// helper functions -- no need to look at these
type testLogger struct {
	prefix string
}

func NewLogger(prefix string) testLogger {
	return testLogger{prefix: prefix}
}

func (l testLogger) log(message string) {
	fmt.Printf("[%s][%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), l.prefix, message)
}

func (l testLogger) TestResult(description string, success bool) {
	var label string
	if success {
		label = "OK"
	} else {
		label = "ERROR"
	}

	l.log(fmt.Sprintf("%-70s%-10s", description, label))
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s [server-address]\n", os.Args[0])
	os.Exit(1)
}

func reportError(err error) {
	timeWarning := []string{}

	deadlineTime, _ := time.Parse(time.RFC3339, DEADLINE)
	timeLeft := deadlineTime.Sub(time.Now())
	totalHours := timeLeft.Hours()
	daysLeft := int(totalHours / 24)
	hoursLeft := int(totalHours) - 24*daysLeft

	if daysLeft > 0 {
		timeWarning = append(timeWarning, fmt.Sprintf("%d days", daysLeft))
	}

	if hoursLeft > 0 {
		timeWarning = append(timeWarning, fmt.Sprintf("%d hours", hoursLeft))
	}

	timeWarning = append(timeWarning, fmt.Sprintf("%d minutes", int(timeLeft.Minutes())-60*int(totalHours)))
	warning := strings.Join(timeWarning, ", ")

	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	fmt.Fprintf(os.Stderr, "\nPlease fix the bug above and run this test again. Time remaining before deadline: %s\n", warning)
	os.Exit(1)
}

//////////////////////////////////////////////////////////////////////

func clientA(serverAddr, localIP, localPath string) (err error) {
	var blob dfslib.Chunk
	var dfs dfslib.DFS

	logger := NewLogger("Client A")
	content := "CPSC 416: Hello World!"

	testCase := fmt.Sprintf("Mounting DFS('%s', '%s', '%s')", serverAddr, localIP, localPath)

	dfs, err = dfslib.MountDFS(serverAddr, localIP, localPath)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}
	logger.TestResult(testCase, true)

	defer func() {
		// if the client is ending with an error, do not make thing worse by issuing
		// extra calls to the server
		if err != nil {
			return
		}

		if err = dfs.UMountDFS(); err != nil {
			logger.TestResult("Unmounting DFS", false)
			return
		}

		logger.TestResult("Unmounting DFS", true)
	}()

	testCase = fmt.Sprintf("Attempt to open file '%s' fails", INVALID_FILE_NAME)

	_, err = dfs.Open(INVALID_FILE_NAME, dfslib.WRITE)
	if err == nil {
		logger.TestResult(testCase, false)
		return fmt.Errorf("Opening invalid file name '%s' did not cause an error", INVALID_FILE_NAME)
	}

	logger.TestResult(testCase, true)

	testCase = fmt.Sprintf("Opening file '%s' for writing", VALID_FILE_NAME)

	file, err := dfs.Open(VALID_FILE_NAME, dfslib.WRITE)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}
	defer func() {
		if err != nil {
			return
		}

		testCase := fmt.Sprintf("Closing file '%s'", VALID_FILE_NAME)

		err = file.Close()
		if err != nil {
			logger.TestResult(testCase, false)
			return
		}

		logger.TestResult(testCase, true)
	}()

	logger.TestResult(testCase, true)

	testCase = fmt.Sprintf("Reading empty chunk %d", CHUNKNUM)

	err = file.Read(CHUNKNUM, &blob)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}

	for i := 0; i < 32; i++ {
		if blob[i] != 0 {
			logger.TestResult(testCase, false)
			return fmt.Errorf("Byte %d at chunk %d expected to be zero, but is %v", i, CHUNKNUM, blob[i])
		}
	}
	logger.TestResult(testCase, true)

	testCase = fmt.Sprintf("Writing chunk %d", CHUNKNUM)

	copy(blob[:], content)
	err = file.Write(CHUNKNUM, &blob)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}
	logger.TestResult(testCase, true)

	testCase = fmt.Sprintf("Able to read '%s' back from chunk %d", content, CHUNKNUM)

	err = file.Read(CHUNKNUM, &blob)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}

	str := string(blob[:len(content)])

	if str != content {
		logger.TestResult(testCase, false)
		return fmt.Errorf("Reading from chunk %d. Expected: '%s'; got: '%s'", CHUNKNUM, content, str)
	}
	logger.TestResult(testCase, true)

	return
}

func clientB(serverAddr, localIP, localPath string) (err error) {
	var dfs dfslib.DFS

	logger := NewLogger("Client B")

	testCase := fmt.Sprintf("Mounting DFS('%s', '%s', '%s')", serverAddr, localIP, localPath)

	dfs, err = dfslib.MountDFS(serverAddr, localIP, localPath)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}
	logger.TestResult(testCase, true)


	defer func() {
		// if the client is ending with an error, do not make thing worse by issuing
		// extra calls to the server
		if err != nil {
			return
		}

		if err = dfs.UMountDFS(); err != nil {
			logger.TestResult("Unmounting DFS", false)
			return
		}

		logger.TestResult("Unmounting DFS", true)
	}()


	testCase = fmt.Sprintf("File '%s' exists globally", VALID_FILE_NAME)

	exists, err := dfs.GlobalFileExists(VALID_FILE_NAME)
	if err != nil {
		logger.TestResult(testCase, false)
		return
	}

	if !exists {
		err = fmt.Errorf("Expected file '%s' to exist globally", VALID_FILE_NAME)
		logger.TestResult(testCase, false)
		return
	}

	logger.TestResult(testCase, true)

	testCase = fmt.Sprintf("Opening file '%s' for reading test", VALID_FILE_NAME)

	_, err = dfs.Open(VALID_FILE_NAME, dfslib.READ)
	if err == nil {
		logger.TestResult(testCase, false)
		err = fmt.Errorf("Expected opening file '%s' to fail, but it succeeded", VALID_FILE_NAME)
		return
	}

	logger.TestResult(testCase, true)
	err = nil // so that the main function won't report the above (expected) error

	return
}

func main() {
	// usage: ./single_client [server-address]
	if len(os.Args) != 2 {
		usage()
	}

	serverAddr := os.Args[1]
	localIP := "127.0.0.1" // you may want to change this when testing

	// this creates a directory (to be used as localPath) for each client.
	// The directories will have the format "./client{A,B}NNNNNNNNN", where
	// N is an arbitrary number. Feel free to change these local paths
	// to best fit your environment
	clientALocalPath, errA := ioutil.TempDir(".", "clientA")
	clientBLocalPath, errB := ioutil.TempDir(".", "clientB")
	if errA != nil || errB != nil {
		panic("Could not create temporary directory")
	}

	if err := clientA(serverAddr, localIP, clientALocalPath); err != nil {
		reportError(err)
	}

	if err := clientB(serverAddr, localIP, clientBLocalPath); err != nil {
		reportError(err)
	}

	fmt.Printf("\nCONGRATULATIONS! Your DFS implementation correctly handles the single client scenario.\n")
}
