-- Output alerts to a file for ML script
output {
    fast_alert = { filename = "/home/nimisha/snort_project/alert_fast.txt" }
}

-- Include your existing rules
include = "/usr/local/snort/etc/rules/snort3-community-rules/snort3-community-rules.lua"
