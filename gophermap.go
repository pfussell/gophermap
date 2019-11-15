package main

import (
	"fmt"
	"gophermap/parser"
	"io/ioutil"
	"os"
)

// Need to make this a command line argument for
// each type and then the file name
// $ gophermap SCAN_TYPE filename.xml
func main() {
	usage := `     
	.\gophermap [FILE-TYPE] [file.ext]
	 file type can be [nessus, nmap, rumble]
	`

	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Println(usage)
		os.Exit(3)
	}

	switch args[0] {
	case "nessus":
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		parser.NessusPrettyPrint(args[1])
	case "nmap":
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		fl, err := ioutil.ReadFile(args[1])
		if err != nil {
			fmt.Println("Error opening file!")
		}
		parser.NmapPrettyPrint(fl)

	case "rumble":
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		fl, err := ioutil.ReadFile(args[1])
		if err != nil {
			fmt.Println("Error opening file!")
		}
		parser.RumblePrettyPrint(fl)

	default:
		fmt.Println("Select  file type that exists")
		os.Exit(3)
	}

}
