package cmd

import (
	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var nessusCsvWebCmd = &cobra.Command{
	Use:   "nessus-csv-web",
	Short: "Read the Nessus csv output and print out all detected web servers",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		p := parser.New(filePath, nil, Verbose)
		p.NessusPrettyWebCSV()
	},
}

func init() {
	rootCmd.AddCommand(nessusCsvWebCmd)
	nessusCsvSrvCmd.Flags().StringVarP(&filePath, "PATH", "f", "", "Nessus CSV file to parse")
}
