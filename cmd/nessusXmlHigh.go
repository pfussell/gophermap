package cmd

import (
	"fmt"

	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var nessusXmlHighCmd = &cobra.Command{
	Use:   "nessus-xml-high",
	Short: "parse high/crit vulns from nessus xml",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nessus-xml-high called")
		p := parser.New(args[0], nil)
		p.NessusPrettyHighCritXML()
	},
}

func init() {
	rootCmd.AddCommand(nessusXmlHighCmd)
}
