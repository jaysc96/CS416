

package main

// Expects blockartlib.go to be in the ./blockartlib/ dir, relative to
// this art-app.go file
// import "./blockartlib"
import "bufio"
import "fmt"
import "os"
import "io"
import "strings"
// import "crypto/ecdsa"

func main() {
	// minerAddr := "127.0.0.1:8080"
	// privKey := // TODO: use crypto/ecdsa to read pub/priv keys from a file argument.

	snr := bufio.NewScanner(os.Stdin)
  enter := "Enter your command:"
  for fmt.Println(enter); snr.Scan(); fmt.Println(enter) {
      line := snr.Text()
      if len(line) == 0 {
          break
      }
      fields := strings.Fields(line)
			// fmt.Printf("Fields: %s\n", fields[0])
			if fields[0] != "" {
				parseCommand(fields)
			}


      fmt.Printf("Fields: %q\n", fields)
  }
  if err := snr.Err(); err != nil {
      if err != io.EOF {
          fmt.Fprintln(os.Stderr, err)
      }
  }
}

func parseCommand(input []string) {
	// validateNum := 2
	// fmt.Printf("Success in parseCommand")
	if input[0] == "AddShape"{
		fmt.Printf("Success in A")
		/*
		shapeHash, blockHash, ink, err := canvas.AddShape(validateNum, blockartlib.PATH, "M 0 0 L 0 5", "transparent", "red")
		if checkError(err) != nil {
			return
		}*/
	} else
	if input[0] == "DeleteShape"{
		fmt.Printf("Success in D")
		/*ink3, err := canvas.DeleteShape(validateNum, shapeHash)
		if checkError(err) != nil {
			return
		}*/
	} else
	if input[0] == "OpenCanvas"{
		fmt.Printf("Success in O")
		/*canvas, settings, err := blockartlib.OpenCanvas(minerAddr, privKey)
		if checkError(err) != nil {
			return
		}*/
	} else
	if input[0] == "CloseCanvas"{
		fmt.Printf("Success in C")
		/*ink4, err := canvas.CloseCanvas()
		if checkError(err) != nil {
			return
		}*/
	}
}

func checkError(err error) error {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error ", err.Error())
		return err
	}
	return nil
}
