rule AgentTesla_Malware
{
    meta:
        description = "Detects AgentTesla malware based on unique strings and code patterns from various variants"
        author = "Optimized from public YARA rules"
        family = "AgentTesla Stealer"
        date = "2025-12-15"
        reference = "Analysis of public rules from Stormshield, Elastic Security, and others"

    strings:
        // Strings from credential stealing functions
        $cred1 = "GetMozillaFromLogins" ascii fullword
        $cred2 = "GetMozillaFromSQLite" ascii fullword
        $cred3 = "VaultGetItem_WIN7" ascii fullword
        $cred4 = "SafariDecryptor" ascii fullword

        // Configuration and account strings
        $conf1 = "AccountConfiguration+username" wide fullword
        $conf2 = "MailAccountConfiguration" ascii fullword
        $conf3 = "SmtpAccountConfiguration" ascii fullword
        $conf4 = "get_GuidMasterKey" ascii fullword

        // Feature-specific strings
        $feat1 = "KillTorProcess" ascii fullword
        $feat2 = "EnableScreenLogger" ascii fullword
        $feat3 = "PublicIpAddressGrab" ascii fullword
        $feat4 = "EnableTorPanel" ascii fullword
        $feat5 = "MozillaBrowserList" ascii fullword
        $feat6 = "TelegramLog" ascii fullword

        // HTML report strings from Stormshield rule
        $html1 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html2 = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html3 = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html4 = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html5 = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

        // Obfuscated byte sequences from Elastic rules (selected for specificity)
        $seq1 = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }
        $seq2 = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }

    condition:
        6 of ($cred*, $conf*, $feat*) or
        3 of ($html*) or
        all of ($seq*)
}