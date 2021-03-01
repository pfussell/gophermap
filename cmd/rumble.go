package cmd

import (
	"fmt"

	"github.com/pafussell/gophermap/parser"
	"github.com/spf13/cobra"
)

var rumbleCmd = &cobra.Command{
	Use:   "rumble",
	Short: "Read in a  rumble-nmap xml file and print out all found services and versions by IP address",
	Long: `note: that while rumble uses the nmap xml format it also seems to be hiding 
a lot of version data in banners in the JSON blob. Thus the dedicated format. `,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("rumble called")
		p := parser.New(args[0], nil)
		p.RumblePrettyPrint()
	},
}

func init() {
	rootCmd.AddCommand(rumbleCmd)
}
