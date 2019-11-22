package main

import (
	"fmt"
	"gophermap/parser"
	"io/ioutil"
	"os"
)

func main() {
	usage := `
	For the moment gophermap will just take a scan file and output 
	enumerated services in a format something like :
	| host-ip | port | service version | 


	Usage: 
	  .\gophermap [command] [file.ext]
	  file type can be [nessus-csv, nessus-csv-web,nessus-xml-srv, nessus-xml-high, nmap, rumble]
		note: that while rumble uses the nmap xml format it also seems to be hiding 
		a lot of version data in banners in the JSON blob. Thus the dedicated
		format. 

		Commands:
		gophermap
		  nessus-csv          -- read the Nessus csv output and print out services found by the "Service Detection" plugin 
		  nessus-csv-web      -- read the Nessus csv output and print out all detected web servers 
		  nessus-xml          -- read the Nessus xml output and print out services found by the "Service Detection" plugin 
		  nmap                -- read in an nmap xml file and print out all found services and versions by IP address
		  rumble              -- read in a  rumble-nmap xml file and print out all found services and versions by IP address
		  
	`

	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Println(usage)
		os.Exit(3)
	}

	// gophermap currently accepts 3 scan file formats [nmapxml, rumblexml, nessus csv]
	switch args[0] {
	case "nessus-csv":
		// check if file (2nd arg) exists; exit if not
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

	case "nessus-csv-web":
		// check if file (2nd arg) exists; exit if not
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		// parse the csv
		parser.NessusPrettyWeb(args[1])

	case "nessus-xml-srv":
		// check if file (2nd arg) exists; exit if not
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		fl, err := ioutil.ReadFile(args[1])
		if err != nil {
			fmt.Println("Error opening file!")
		}

		// parse the csv
		parser.NessusPrettyServiceXML(fl)

	case "nessus-xml-high":
		// check if file (2nd arg) exists; exit if not
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		fl, err := ioutil.ReadFile(args[1])
		if err != nil {
			fmt.Println("Error opening file!")
		}

		// parse the csv
		parser.NessusPrettyHighCritXML(fl)

	case "nmap":
		// check if file (2nd arg) exists; exit if not
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		// open the file with ReadFile;
		fl, err := ioutil.ReadFile(args[1])
		if err != nil {
			fmt.Println("Error opening file!")
		}
		// pass opened file (byte slice)
		parser.NmapPrettyPrint(fl)

	case "rumble":
		// check if file (2nd arg) exists; exit if not
		if _, err := os.Stat(args[1]); os.IsNotExist(err) {
			fmt.Println("Scan file does not exist")
			os.Exit(1)
		}

		// ReadFile returns contents as byte slice
		fl, err := ioutil.ReadFile(args[1])
		if err != nil {
			fmt.Println("Error opening file!")
		}

		// parse file
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
