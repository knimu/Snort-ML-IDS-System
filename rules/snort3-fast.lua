-- Network variables
HOME_NET = '192.168.10.0/24'
EXTERNAL_NET = 'any'

-- DAQ configuration (interface to sniff)
daq = {
    type = 'pcap',       -- Changed from afpacket to pcap
    interface = 'ens37'
}

-- Path to rules
local rules_path = '/usr/local/snort/etc/rules/'

-- Load your local.rules file
include(rules_path .. 'local.rules')

-- Output configuration for fast alert logging
outputs = {
    fast = {
        filename = '/home/nimisha/snort_project/alert_fast.txt'
    }
}

-- IPS mode (empty means detection only)
ips = {}
