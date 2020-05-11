package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pafussell/gophermap/parser"
)

// for csv files
func checkfile(file string) {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println("Scan file does not exist")
		os.Exit(1)
	}
}

// for any function that takes in a byte slice
func checkfileGetbyte(file string) []byte {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println("Scan file does not exist")
		os.Exit(1)
	}

	fl, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Error opening file!")
	}

	return fl
}

func main() {
	usage := `
	Usage: 
	  .\gophermap [command] [file.ext]
		
		Commands:
		gophermap
		  nessus-csv-srv          -- read the Nessus csv output and print out services found by the "Service Detection" plugin 
		  nessus-csv-web      -- read the Nessus csv output and print out all detected web servers 
		  nessus-xml          -- read the Nessus xml output and print out services found by the "Service Detection" plugin 
		  nmap                -- read in an nmap xml file and print out all found services and versions by IP address
		  rumble              -- read in a  rumble-nmap xml file and print out all found services and versions by IP address

		  note: that while rumble uses the nmap xml format it also seems to be hiding 
			a lot of version data in banners in the JSON blob. Thus the dedicated
			format. 
		  
	`

	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Println(usage)
		os.Exit(3)
	}

	switch args[0] {
	case "nessus-csv-srv":
		// check if file (2nd arg) exists; exit if not
		checkfile(args[1])
		parser.NessusPrettyServicesCSV(args[1])

	case "nessus-csv-web":
		// check if file (2nd arg) exists; exit if not
		checkfile(args[1])
		parser.NessusPrettyWebCSV(args[1])

	case "nessus-xml-srv":
		fl := checkfileGetbyte(args[1])
		parser.NessusPrettyServiceXML(fl)

	case "nessus-xml-high":
		// check if file (2nd arg) exists; exit if not; return byte slice
		fl := checkfileGetbyte(args[1])
		parser.NessusPrettyHighCritXML(fl)

	case "nmap":
		// check if file (2nd arg) exists; exit if not; return byte slice
		fl := checkfileGetbyte(args[1])
		parser.NmapPrettyPrint(fl)

	case "rumble":
		// check if file (2nd arg) exists; exit if not; return byte slice
		fl := checkfileGetbyte(args[1])
		parser.RumblePrettyPrint(fl)

	case "help":
		fmt.Println(usage)

	default:
		// report and exit if not of the 3 file types above
		fmt.Println("Error: Select  file type that exists")
		fmt.Println(usage)
		os.Exit(3)
	}

}
