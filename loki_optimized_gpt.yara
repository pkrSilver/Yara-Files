rule Loki_Optimized
{
    meta:
        description = "Detects Loki malware family with minimal false positives"
        author = "AutoYara + Analyst"
        date = "2025-12-08"
    strings:
        // Keep only the most specific and rare strings
        $s0 = { 24 E9 0B B1 87 7C 6F 2F 11 4C 68 58 AB 1D 61 C1 3D 2D 66 B6 90 41 DC 76 06 71 DB 01 BC 20 D2 98 }
        $s1 = { 6F 2A 37 BE 0B B4 A1 8E 0C C3 1B DF 05 5A 8D EF 02 2D C0 15 F0 D8 78 C2 CE 11 A4 9E 44 45 53 54 }
        $s2 = { 67 07 72 13 57 00 05 82 4A BF 95 14 7A B8 E2 AE 2B B1 7B 38 1B B6 0C 9B 8E D2 92 0D BE D5 E5 B7 }
        $s3 = { 32 C8 AD 89 AC 16 AD 52 69 63 68 88 AC 16 AD 00 00 00 00 00 00 00 00 50 45 00 00 4C 01 04 00 85 }
        $s4 = { 61 76 2E 72 75 00 00 00 00 00 14 C9 BC BF A8 F8 72 29 C5 F9 5A 41 41 5D CA E8 A8 11 13 C0 A2 DF }
        $s5 = { 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 CC CD 78 FE 88 AC 16 AD 88 AC 16 AD }
        $s6 = { 6E 74 69 6D 65 52 65 73 6F 75 72 63 65 53 65 74 02 00 00 00 00 00 00 00 00 00 00 00 50 41 44 50 }
        $s7 = { 6F 6E 00 53 79 73 74 65 6D 2E 47 6C 6F 62 61 6C 69 7A 61 74 69 6F 6E 00 53 79 73 74 65 6D 2E 52 }
        $s8 = { 70 53 65 72 76 69 63 65 73 00 53 79 73 74 65 6D 2E 52 75 6E 74 69 6D 65 2E 43 6F 6D 70 69 6C 65 }
        $s9 = { 6E 74 48 61 6E 64 6C 65 72 00 53 79 73 74 65 6D 2E 43 6F 64 65 44 6F 6D 2E 43 6F 6D 70 69 6C 65 }
        $s10 = { 00 41 73 73 65 6D 62 6C 79 46 69 6C 65 56 65 72 73 69 6F 6E 41 74 74 72 69 62 75 74 65 00 41 73 }
        $s11 = { 6C 65 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 54 72 61 64 65 6D 61 72 6B 41 74 74 }
        $s12 = { 37 66 31 31 64 35 30 61 33 61 05 01 00 00 00 15 53 79 73 74 65 6D 2E 44 72 61 77 69 6E 67 2E 42 }
        $s13 = { 01 00 CE CA EF BE 01 00 00 00 91 00 00 00 6C 53 79 73 74 65 6D 2E 52 65 73 6F 75 72 63 65 73 2E }
        $s14 = { 00 00 99 54 CD 3C A8 87 10 4B A2 15 60 88 88 DD 3B 55 00 00 00 00 00 00 00 00 00 00 00 00 01 00 }
        $s15 = { 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 }
        $s16 = { 75 70 70 6F 72 74 65 64 4F 53 20 49 64 3D 22 7B 33 35 31 33 38 62 39 61 2D 35 64 39 36 2D 34 66 }
        // ...add more if you find Loki-specific strings...

    condition:
        6 of ($s*) // Adjust threshold based on testing
}
