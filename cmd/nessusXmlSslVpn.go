package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var nessusXmlSslVpnCmd = &cobra.Command{
	Use:   "nessus-xml-ssl-vpn",
	Short: "parse high/crit vulns from nessus xml",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nessus-xml-ssl-vpn not implemented")
	},
}

func init() {
	rootCmd.AddCommand(nessusXmlSslVpnCmd)
}
