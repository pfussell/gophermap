package cmd

import (
	"fmt"

	"github.com/pafussell/gophermap/parser"

	"github.com/spf13/cobra"
)

var nmapCmd = &cobra.Command{
	Use:   "nmap",
	Short: "Read in an nmap xml file and print out all found services and versions by IP address",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("nmap called, file = %v\n", args[0])
		p := parser.New(args[0], nil)
		p.NmapPrettyPrint()
	},
}

func init() {
	rootCmd.AddCommand(nmapCmd)
}
