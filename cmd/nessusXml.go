package cmd

import (
	"fmt"

	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var nessusXmlCmd = &cobra.Command{
	Use:   "nessus-xml",
	Short: "Read the Nessus xml output and print out services found by the \"Service Detection\" plugin",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nessus-xml called")
		p := parser.New(args[0], nil)
		p.NessusPrettyServiceXML()
	},
}

func init() {
	rootCmd.AddCommand(nessusXmlCmd)
}
