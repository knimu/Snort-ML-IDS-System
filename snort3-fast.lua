-- FINAL WORKING CONFIG

HOME_NET = '192.168.10.0/24'

daq =
{
    module = 'pcap'
}

daq_mode = 'passive'

interfaces = { 'ens37' }

ips =
{
    enable_builtin_rules = true,
    rules = [[
        include /etc/snort/rules/local.rules
    ]]
}

output =
{
    alert_fast =
    {
        file = true,
        filename = '/home/nimisha/snort_project/alert_fast.txt'
    }
}
