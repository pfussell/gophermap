package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

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
				// fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Service.Product, port.Service.Version)
				fmt.Printf("| %18s | %8s | %6s | %-22s %-8s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, port.Service.Product, port.Service.Version)
			}

		}
	}
}

// NessusPrettyPrint consumes an nessus csv and
// prints out service and IP
func NessusPrettyPrint(fl string) {
	// Open the file
	csvfile, err := os.Open(fl)
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
			fmt.Printf("| %14s | %8s | %22s\n", record[4], record[6], record[12])
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
				if port.Service.Product != "" {
					fmt.Printf("| %18s | %8s | %6s | %-22s %-8s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, port.Service.Product, port.Service.Version)
				} else {
					m := make(map[string]string)
					b := []byte(port.Scripts[0].Output)
					err := json.Unmarshal(b, &m)
					if err != nil {
						fmt.Println("Error parsing embedded JSON")
					} else {
						if banner, exists := m["banner"]; exists {
							fmt.Printf("| %18s | %8s | %6s | %-22s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, banner)
							// fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Protocol, " | ", " UNKNOWN ", " | ", banner)
						}
					}
				}
			}
		}
	}
}
