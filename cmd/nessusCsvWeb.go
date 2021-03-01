package cmd

import (
	"fmt"

	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var nessusCsvWebCmd = &cobra.Command{
	Use:   "nessus-csv-web",
	Short: "Read the Nessus csv output and print out all detected web servers",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nessus-csv-web called")
		p := parser.New(args[0], nil)
		p.NessusPrettyWebCSV()
	},
}

func init() {
	rootCmd.AddCommand(nessusCsvWebCmd)
}
