rule Vidar_Optimized
{
    meta:
        description = "Detects Vidar malware family with minimal false positives"
        author = "AutoYara + Analyst"
        date = "2025-12-14"
    strings:
        // Keep only the most specific and rare strings
        $s0 = "formanceFrequenc" ascii
        $s1 = { F0 3F 00 E4 0B 54 02 00 00 00 00 00 10 63 2D 5E }
        $s2 = { C1 92 C8 3C E4 31 3B 52 12 29 18 79 CE CB 45 9E 20 89 D7 1F 35 DB 23 B5 30 4A 8D 5E 59 15 E6 8B }
        $s3 = { 8F 84 13 00 00 31 C1 89 C8 C1 E0 07 25 80 56 2C }
        $s4 = { 41 54 56 57 53 48 83 EC 58 48 8D 6C 24 50 48 8B }
        $s5 = { 00 48 89 F0 48 83 C4 40 5E C3 CC CC CC CC CC CC }
        $s6 = { 0A 00 00 5B 5D 5F 5E 41 5C 41 5D 41 5E 41 5F C3 }
        $s7 = { 5E 41 5F C3 CC CC 41 57 41 56 41 55 41 54 56 57 }
        $s8 = { 5F C3 CC CC CC CC CC CC CC CC 41 57 41 56 41 55 }
        $s9 = { 48 8B 44 24 28 48 8B 00 48 8B 4C 24 28 FF 50 08 }
        $s10 = { 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F }
        $s11 = { 00 55 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74 69 }
        $s12 = { 00 4C 89 F0 48 83 C4 38 5B 5F 5E 41 5E C3 CC CC }
        $s13 = { 0D 0A 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C }
        $s14 = { 00 48 89 F0 48 83 C4 40 5E C3 CC CC CC CC CC CC }
        $s15 = { 5E C3 41 57 41 56 41 55 41 54 56 57 55 53 48 83 }
        // ...add more if you find Vidar-specific strings...

    condition:
        6 of ($s*) // Adjust threshold based on testing
}
