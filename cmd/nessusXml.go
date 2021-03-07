package cmd

import (
	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var nessusXmlCmd = &cobra.Command{
	Use:   "nessus-xml-srv",
	Short: "Read the Nessus xml output and print out services found by the \"Service Detection\" plugin",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		p := parser.New(filePath, nil, Verbose)
		p.NessusPrettyServiceXML()
	},
}

func init() {
	rootCmd.AddCommand(nessusXmlCmd)
}
