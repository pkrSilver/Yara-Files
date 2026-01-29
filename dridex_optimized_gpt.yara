rule Dridex_Optimized
{
    meta:
        description = "Detects Dridex malware family with minimal false positives"
        author = "AutoYara + Analyst"
        date = "2025-12-14"
    strings:
        // Keep only the most specific and rare strings
        $s0 = { C1 92 C8 3C E4 31 3B 52 12 29 18 79 CE CB 45 9E 20 89 D7 1F 35 DB 23 B5 30 4A 8D 5E 59 15 E6 8B }
        $s1 = { 14 93 A8 11 4D 22 D1 09 92 BD D6 8E 0E B6 F9 AC C9 19 B8 BF F3 AF 6C 3F 0F 56 1B 50 A9 4B D9 3A }
        $s2 = { 6C 00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32 00 4C 64 72 47 65 74 50 72 6F 63 65 64 75 72 }
        $s3 = { 53 65 72 76 69 63 65 44 69 73 70 6C 61 79 4E 61 6D 65 57 00 00 41 44 56 41 50 49 33 32 2E 64 6C }
        $s4 = { 39 E3 AB DE C0 DE C0 3F 00 00 00 00 00 00 00 00 }
        $s5 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 }
        $s6 = { 01 00 4C 00 65 00 67 00 61 00 6C 00 54 00 72 00 61 00 64 00 65 00 6D 00 61 00 72 00 6B 00 73 00 }
        $s7 = { 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F }
        // ...add more if you find Dridex-specific strings...

    condition:
        4 of ($s*) // Adjust threshold based on testing
}
