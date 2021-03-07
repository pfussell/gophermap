package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gophermap",
	Short: "A parser for various network and vulnerability tools and formats",
	Long:  `A parser for Nessus, NMap and Rumble scanner results file in various formats`,
}

var Verbose bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
