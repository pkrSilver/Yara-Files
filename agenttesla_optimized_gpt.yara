rule AgentTesla_Optimized
{
    meta:
        description = "Detects AgentTesla malware family with minimal false positives"
        author = "AutoYara + Analyst"
        date = "2025-12-08"
    strings:
        // Keep only the most specific and rare strings
        $s0 = "ExeMain" ascii
        $s1 = "get_Coun" ascii
        $s2 = "Maximize" ascii
        $s3 = "VAPI32.d" ascii
        $s4 = "CreateFi" ascii
        $s5 = "System.Li" ascii
        $s6 = "FileVers" ascii
        $s7 = "Version=" ascii
        $s8 = "get_Wid" ascii
        $s9 = "rrentPro" ascii
        $s10 = "Register" ascii
        $s11 = "Uninitia" ascii
        $s12 = "Terminat" ascii
        $s13 = "escripti" ascii
        $s14 = "Director" ascii
        $s15 = "MaximizeB" ascii
        // ...add more if you find AgentTesla-specific strings...

    condition:
        15 of ($s*) // Adjust threshold based on testing
}
