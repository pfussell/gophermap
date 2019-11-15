package main

import (
	"gophermap/parser"
)

// Need to make this a command line argument for
// each type and then the file name
// $ gophermap SCAN_TYPE filename.xml 
func main() {
	//fl, err := ioutil.ReadFile("test.xml")
	//if err != nil {
	//	fmt.Println("Error: ", err)
	//}

	//prettyPrint(fl)
	parser.NessusPrettyPrint()
	
}