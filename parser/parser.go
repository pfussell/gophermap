package parser

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"

	gne "github.com/tomsteele/go-nessus"
	gn "github.com/tomsteele/go-nmap"
)

type Parser struct {
	FilePath string
	Logger   io.Writer
}

func New(file string, out io.Writer) (p *Parser) {
	if out != nil {
		p = &Parser{FilePath: file, Logger: out}
	} else {
		p = &Parser{FilePath: file, Logger: os.Stdout}
	}
	return
}

func (p *Parser) getNmapParser(w io.Writer) (*gn.NmapRun, error) {
	fb, err := ioutil.ReadFile(p.FilePath)
	if err != nil {
		fmt.Fprintf(w, "Error opening scan file: %v\n", p.FilePath)
		return nil, err
	}

	n, err := gn.Parse(fb)
	if err != nil {
		fmt.Fprintf(w, "Error parsing NMap file\n")
		return nil, err
	}
	return n, nil
}

func (p *Parser) getNessusParser(w io.Writer) (*gne.NessusData, error) {
	fb, err := ioutil.ReadFile(p.FilePath)
	if err != nil {
		fmt.Fprintf(w, "Error opening Nessus file: %v\n", p.FilePath)
		return nil, err
	}

	n, err := gne.Parse(fb)
	if err != nil {
		fmt.Fprintf(w, "Error parsing Nessus file\n")
		return nil, err
	}
	return n, nil
}

func (p *Parser) getCsvRecords(w io.Writer) ([][]string, error) {
	fb, err := ioutil.ReadFile(p.FilePath)
	if err != nil {
		fmt.Fprintf(w, "Error opening Nessus file: %v\n", p.FilePath)
		return nil, err
	}
	br := bytes.NewReader(fb)
	cr := csv.NewReader(br)
	records, err := cr.ReadAll()

	return records, err
}

// NmapPrettyPrint consumes NMap XML and prints
// formatted table of enumerated services
func (p *Parser) NmapPrettyPrint() (err error) {
	np, err := p.getNmapParser(p.Logger)
	if err != nil {
		return err
	}

	// In my previous nmap parser I built a lot more logic into output options I would like to add next
	// eg. ouput live hosts, output just a selected port
	for _, host := range np.Hosts {
		for _, ip := range host.Addresses {
			for _, port := range host.Ports {
				// fmt.Println("| ", ip.Addr, " | ", port.PortId, " | ", port.Service.Product, port.Service.Version)
				fmt.Fprintf(p.Logger, "| %18s | %8s | %6s | %-22s %-8s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, port.Service.Product, port.Service.Version)
			}

		}
	}

	return
}

// NessusPrettyServiceXML does a pretty print of nessus data
// and takes in the .nessus style file
func (p *Parser) NessusPrettyServiceXML() (err error) {
	np, err := p.getNessusParser(p.Logger)
	if err != nil {
		return err
	}

	// we might need some better logic here. Right now we just look for the plugin named
	// Service Detection and output the plugin output with the port. Might be other plugins
	// we want to add that have good data.
	for _, host := range np.Report.ReportHosts {
		for _, item := range host.ReportItems {
			// change this...need to range over host properties to get tag == ip
			if item.PluginName == "Service Detection" && item.PluginOutput[0:17] != "The service close" {
				fmt.Fprintf(p.Logger, "| %18s | %8s | %-10s| %-32s |\n", host.Name, strconv.Itoa(item.Port), item.SvcName, item.PluginOutput[0:28])
			}
		}
	}
	return
}

// NessusPrettyHighCritXML does a pretty print of nessus data
// and takes in the .nessus style file; it prints all high and crit level findings
func (p *Parser) NessusPrettyHighCritXML() (err error) {
	np, err := p.getNessusParser(p.Logger)
	if err != nil {
		return err
	}

	// we might need some better logic here. Right now we just look for the plugin named
	// Service Detection and output the plugin output with the port. Might be other plugins
	// we want to add that have good data.
	for _, host := range np.Report.ReportHosts {
		for _, item := range host.ReportItems {
			// change this...need to range over host properties to get tag == ip
			if item.Severity == 3 || item.Severity == 4 {
				fmt.Fprintf(p.Logger, "| %18s | %8s | %-28s \n", host.Name, strconv.Itoa(item.Port), item.PluginName)
			}
		}

	}
	return
}

// NessusPrettyServicesCSV consumes an nessus csv and
// prints out service and IP
func (p *Parser) NessusPrettyServicesCSV() (err error) {
	records, err := p.getCsvRecords(p.Logger)
	if err != nil {
		return err
	}

	for row := 0; row < len(records); row++ {
		if records[row][7] == "Service Detection" {
			fmt.Fprintf(p.Logger, "| %14s | %8s | %22s\n", records[row][4], records[row][6], records[row][12])
		}
	}
	return
}

// NessusPrettyWebCSV consumes an nessus csv and
// prints out service and IP
func (p *Parser) NessusPrettyWebCSV() (err error) {
	records, err := p.getCsvRecords(p.Logger)
	if err != nil {
		return err
	}

	for row := 0; row < len(records); row++ {
		if records[row][7] == "HTTP Server Type and Version" {
			re := regexp.MustCompile("\\n")
			input := records[row][12]
			input = re.ReplaceAllString(input, " ")
			fmt.Fprintf(p.Logger, "| %14s | %8s | %22s\n", records[row][4], records[row][6], input)
		}
	}
	return
}

// RumblePrettyPrint is for parsing
// Rumble scans in nmap xml format
func (p *Parser) RumblePrettyPrint() (err error) {
	n, err := p.getNmapParser(p.Logger)
	if err != nil {
		return err
	}

	for _, host := range n.Hosts {
		for _, ip := range host.Addresses {
			fmt.Println("|--------------|-------------------|--------------|------------------|")
			// im getting blank lines in the return and I can't figure out why
			if ip.Addr == "" {
				continue
			} else {
				for _, port := range host.Ports {
					if port.Service.Product != "" {
						fmt.Fprintf(p.Logger, "| %18s | %8s | %6s | %-22s %-8s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, port.Service.Product, port.Service.Version)
						continue
					}
					m := make(map[string]string)
					b := []byte(port.Scripts[0].Output)
					if err := json.Unmarshal(b, &m); err != nil {
						fmt.Fprintf(p.Logger, "Error parsing embedded JSON\n")
					}
					if banner, exists := m["banner"]; exists {
						fmt.Fprintf(p.Logger, "| %18s | %8s | %6s | %-22s |\n", ip.Addr, strconv.Itoa(port.PortId), port.Protocol, banner)
					}
				}
			}
		}
	}
	return
}
