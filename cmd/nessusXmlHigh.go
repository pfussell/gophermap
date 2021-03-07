package cmd

import (
	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var nessusXmlHighCmd = &cobra.Command{
	Use:   "nessus-xml-high",
	Short: "parse high/crit vulns from nessus xml",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		p := parser.New(filePath, nil, Verbose)
		p.NessusPrettyHighCritXML()
	},
}

func init() {
	rootCmd.AddCommand(nessusXmlHighCmd)
}
