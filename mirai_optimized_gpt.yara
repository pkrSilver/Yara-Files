rule Mirai_Optimized
{
    meta:
        description = "Detects Mirai malware family (low specificity, high FP risk)"
        author = "AutoYara + Analyst"
        date = "2025-12-08"
    strings:
        // These are not highly specific, but kept for demonstration
        $s0 = { 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 }
        $s1 = "oo many references: cannot splic" ascii
        $s2 = "dress family not supported by pr" ascii
        $s3 = { 00 4F 70 65 72 61 74 69 6F 6E 20 6E 6F 74 20 70 65 72 6D 69 74 74 65 64 00 4E 6F 20 73 75 63 68 20 66 69 6C 65 20 6F 72 20 64 69 72 65 63 74 6F 72 79 00 4E 6F 20 73 75 63 68 20 70 72 6F 63 65 }
        $s4 = { 00 49 6E 76 61 6C 69 64 20 65 78 63 68 61 6E 67 65 00 49 6E 76 61 6C 69 64 20 72 65 71 75 65 73 74 20 64 65 73 63 72 69 70 74 6F 72 00 45 78 63 68 61 6E 67 65 20 66 75 6C 6C 00 4E 6F 20 61 6E }
        $s5 = { 00 00 00 00 00 00 00 05 CA 7F 16 9C 11 F9 89 00 00 00 00 02 9D 74 8B 45 AA 7B EF B9 9E FE AD 08 19 BA CF 41 E0 16 A2 32 6C F3 CF F4 8E 3C 44 83 C8 8D 51 45 6F 90 95 23 3E 00 97 2B 1C 71 B2 4E }

    condition:
        5 of ($s*) // Increase threshold to reduce FPs
}
