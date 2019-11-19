package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"

	gne "github.com/tomsteele/go-nessus"
	gn "github.com/tomsteele/go-nmap"
)

// NmapPrettyPrint consumes nmap xml and prints
// formatted table of enumed services
func NmapPrettyPrint(f []byte) {
	n, err := gn.Parse(f)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	// In my previous nmap parser I built a lot more logic into output options I would like to add next
	// eg. ouput live hosts, output just a selected port
	for _, host := range n.Hosts {
		for _, ip := range host.Addresses {
			for _, port := range host.Ports {
				// fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Service.Product, port.Service.Version)
				fmt.Printf("| %18s | %8s | %6s | %-22s %-8s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, port.Service.Product, port.Service.Version)
			}

		}
	}
}

// NessusPrettyXML does a pretty print of nessus data
// and takes in the .nessus style file
func NessusPrettyXML(f []byte) {
	n, err := gne.Parse(f)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	// we might need some better logic here. Right now we just look for the plugin named
	// Service Detection and output the plugin output with the port. Might be other plugins
	// we want to add that have good data.
	for _, host := range n.Report.ReportHosts {
		for _, item := range host.ReportItems {
			// change this...need to range over host properties to get tag == ip
			if item.PluginName == "Service Detection" && item.PluginOutput[0:17] != "The service close" {
				fmt.Printf("| %18s | %8s | %-32s |\n", host.Name, strconv.Itoa(item.Port), item.PluginOutput[0:28])
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

// NessusPrettyWeb consumes an nessus csv and
// prints out service and IP
func NessusPrettyWeb(fl string) {
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
		if record[7] == "HTTP Server Type and Version" {
			re := regexp.MustCompile("\\n")
			input := record[12]
			input = re.ReplaceAllString(input, " ")
			fmt.Printf("| %14s | %8s | %22s\n", record[4], record[6], input)
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
