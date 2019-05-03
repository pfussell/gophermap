package main

import (
	"fmt"
	"io/ioutil"

	gn "github.com/tomsteele/go-nmap"
)

func main() {
	fl, err := ioutil.ReadFile("test.xml")
	if err != nil {
		fmt.Println("Error: ", err)
	}

	n, err := gn.Parse(fl)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	for _, host := range n.Hosts {

		for _, ip := range host.Addresses {

			for _, port := range host.Ports {
				fmt.Println(host.Hostnames[0].Name, " | ", ip.Addr, " | ", port.PortId)

			}

		}
	}

}
