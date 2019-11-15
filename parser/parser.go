package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	gn "github.com/tomsteele/go-nmap"
)

// probably need to add files to be opened as arugments
// to these functions

// NmapPrettyPrint consumes nmap xml and prints
// formatted table of enumed services
func NmapPrettyPrint(f []byte) {
	n, err := gn.Parse(f)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	for _, host := range n.Hosts {

		for _, ip := range host.Addresses {

			for _, port := range host.Ports {
				fmt.Println(host.Hostnames[0].Name, " | ", ip.Addr, " | ", port.PortId, " | ", port.Service.Product, port.Service.Version)

			}

		}
	}
}

// NessusPrettyPrint consumes an nessus csv and
// prints out service and IP
func NessusPrettyPrint() {
	// Open the file
	csvfile, err := os.Open("test.csv")
	if err != nil {
		log.Fatalln("Couldn't open the csv file", err)
	}

	// Parse the file
	r := csv.NewReader(csvfile)
	//r := csv.NewReader(bufio.NewReader(csvfile))

	// Iterate through the records
	for {
		// Read each record from csv
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if record[7] == "Service Detection" {
			fmt.Printf("| %14s | %8s | \n", record[4], record[6])
		}
	}

}

// RumblePrettyPrint is for parsing
// Rumble scans in nmap xml format
func RumblePrettyPrint(f []byte) {
	n, err := gn.Parse(f)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	for _, host := range n.Hosts {
		for _, ip := range host.Addresses {
			fmt.Println("|--------------|-------------------|--------------|------------------|")
			for _, port := range host.Ports {
				if port.Service.Product == "" {
					if len(port.Protocol) == 0 {
						fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", "UNKNOWN", " | ", " UNKNOWN ", " | ")
					} else {
						m := make(map[string]string)
						b := []byte(port.Scripts[0].Output)
						err := json.Unmarshal(b, &m)
						if err != nil {
							fmt.Println("Error parsing embedded JSON")
						} else {
							if banner, exists := m["banner"]; exists {
								fmt.Println("*** FOUND BANNER ***")
								fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Protocol, " | ", " UNKNOWN ", " | ", banner)
							}
						}
					}
					fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Protocol, " | ", " UNKNOWN ", " | ")
				} else {
					if len(port.Protocol) == 0 {
						fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", " UNKNOWN ", " | ", port.Service.Product, port.Service.Version, " | ", port.Scripts[0].Output)
					} else {
						fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Protocol, " | ", port.Service.Product, port.Service.Version, " | ", port.Scripts[0].Output)
					}
				}
			}
		}
	}
}
