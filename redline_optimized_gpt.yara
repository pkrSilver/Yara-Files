rule Redline_Optimized
{
    meta:
        description = "Detects Redline malware family with minimal false positives"
        author = "AutoYara + Analyst"
        date = "2025-12-14"
    strings:
        // Keep only the most specific and rare strings
        $s0 = { 48 58 66 3B D0 74 05 8D 46 FF 89 07 5F 5E 5B 5D }
        $s1 = { 00 C0 02 47 6C 6F 62 61 6C 4D 65 6D 6F 72 79 53 }
        $s2 = { 02 47 65 74 54 65 6D 70 46 69 6C 65 4E 61 6D 65 }
        $s3 = { 20 49 64 3D 22 7B 31 66 36 37 36 63 37 36 2D 38 }
        $s4 = { 3D 22 7B 33 35 31 33 38 62 39 61 2D 35 64 39 36 }
        $s5 = { 43 75 72 72 65 6E 74 54 68 72 65 61 64 49 64 00 }
        $s6 = { 00 55 00 6E 00 61 00 62 00 6C 00 65 00 20 00 74 }
        $s7 = { 6F 43 72 65 61 74 65 49 6E 73 74 61 6E 63 65 00 }
        $s8 = { 41 56 74 79 70 65 5F 69 6E 66 6F 40 40 00 00 00 }
        $s9 = { 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A 9B }
        $s10 = { 0C FA 3F 32 D5 1C 5D 49 59 93 BC 33 2D 4A EC 9B }
        $s11 = { 31 F9 FF 5F 5E 33 C0 5B 8B E5 5D C2 08 00 55 8B }
        $s12 = { C4 53 3B 75 44 CD 14 BE 9A AF 3F DE 67 BA 94 39 }
        $s13 = { FE 72 09 8B 48 08 03 CE 3B F9 72 0A 42 83 C0 28 }
        $s14 = { 00 46 00 75 00 6E 00 63 00 74 00 69 00 6F 00 6E }
        $s15 = { 00 55 8B EC 83 E4 F8 83 EC 4C 8B 4D 0C 53 56 57 }
        $s16 = { 00 01 00 20 00 A8 25 00 00 09 00 20 20 00 00 01 }
        $s17 = { 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 43 6F 6D 56 69 73 69 62 6C 65 41 74 74 72 }
        $s18 = { 34 2E 30 01 00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C 61 79 4E 61 6D 65 10 2E 4E 45 }
        $s19 = { 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C }
        $s20 = { D5 EF 89 85 B1 71 1F B5 B6 06 A5 E4 BF 9F 33 D4 B8 E8 A2 C9 07 78 34 F9 00 0F 8E A8 09 96 18 98 }
        $s21 = { F9 D0 C1 8A C1 24 0F D7 0F BE C0 81 E1 04 04 00 00 8B DA 03 D8 83 C3 10 FF 23 80 7A 0E 05 75 11 }
        $s22 = { 65 E8 FF 75 F8 8B 45 FC C7 45 FC FE FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 }
        $s23 = { 3B 54 24 14 77 08 72 07 3B 44 24 10 76 01 4E 33 D2 8B C6 4F 75 07 F7 DA F7 D8 83 DA 00 5B 5E 5F }
        $s24 = { 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 }
        $s25 = { 8B F9 85 F6 74 15 8D 46 FF 50 52 57 E8 54 FB 01 00 83 C4 0C 33 C0 66 89 44 77 FE 5F 5E 5D C3 55 }
        // ...add more as needed, but avoid generic/common strings...

    condition:
        15 of ($s*) // Adjust threshold based on testing
}
