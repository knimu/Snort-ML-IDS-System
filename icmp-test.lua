-- Minimal Snort config for ICMP-only testing

references = default_references
classifications = default_classifications

ips =
{
    enable_builtin_rules = false,  -- DISABLE all built-in rules
    variables = default_variables,
    rules = [[/etc/snort/rules/local.rules]]
}

outputs =
{
    alert_fast =
    {
        file = true,
        filename = "/var/log/snort/alert_fast.txt"
    }
}
