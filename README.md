# gophermap
Advanced interface for dealing with nmap and nmap data written in golang. 

```
Commands:
  gophermap
    nessus-csv          -- read the Nessus csv output and print out services found by the "Service Detection" plugin (NOT IMPLEMENTED)
    nessus-csv-srv      -- parse network services from nessus csv
    nessus-csv-web      -- read the Nessus csv output and print out all detected web servers 
    nessus-xml-high     -- parse high/crit vulns from nessus xml 
    nessus-xml-srv      -- parse network services from nessus xml 
    nessus-xml          -- read the Nessus xml output and print out services found by the "Service Detection" plugin (NOT IMPLEMENTED)
    nessus-xml-sslvpn   -- parse ssl VPNs from nessus xml (NOT IMPLEMENTED)
    nessus-xml-vms      -- (NOT IMPLEMENTED)
    nmap                -- read in an nmap xml file and print out all found services and versions by IP address
    rumble              -- read in a  rumble-nmap xml file and print out all found services and versions by IP address
```