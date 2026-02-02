rule LokiBot_Malware
{
    meta:
        description = "Detects LokiBot malware based on characteristic high-entropy byte sequences likely from encryption tables or keys"
        author = "Optimized from AutoYARA rules"
        family = "LokiBot Stealer"
        date = "2025-12-15"
        reference = "Internal analysis of 50 samples"

    strings:
        // High-entropy byte sequences consistent across samples, possibly RC4 keys or shuffled S-boxes
        $key1 = { 24 E9 0B B1 87 7C 6F 2F 11 4C 68 58 AB 1D 61 C1 3D 2D 66 B6 90 41 DC 76 06 71 DB 01 BC 20 D2 98 }
        $key2 = { 6F 2A 37 BE 0B B4 A1 8E 0C C3 1B DF 05 5A 8D EF 02 2D C0 15 F0 D8 78 C2 CE 11 A4 9E 44 45 53 54 }
        $key3 = { 67 07 72 13 57 00 05 82 4A BF 95 14 7A B8 E2 AE 2B B1 7B 38 1B B6 0C 9B 8E D2 92 0D BE D5 E5 B7 }
        $key4 = { DE 77 9B A2 20 B0 53 F9 BF C6 AB 25 94 4B 4D E3 04 00 81 2D C3 FB F4 D0 22 52 50 28 0F B7 F3 F2 }
        $data1 = { 61 76 2E 72 75 00 00 00 00 00 14 C9 BC BF A8 F8 72 29 C5 F9 5A 41 41 5D CA E8 A8 11 13 C0 A2 DF }

        // Avoid common PE stubs to reduce false positives
        // Sequential low-entropy patterns for additional coverage, but thresholded
        $seq1 = { 70 33 74 33 78 33 7C 33 80 33 84 33 88 33 8C 33 90 33 94 33 98 33 9C 33 A0 33 A4 33 A8 33 AC 33 }
        $seq2 = { 32 D6 32 DA 32 DE 32 E2 32 E6 32 EA 32 EE 32 F2 32 F6 32 FA 32 FE 32 02 33 06 33 0A 33 0E 33 12 }
        $seq3 = { 3C D4 3C D8 3C DC 3C E0 3C E4 3C E8 3C EC 3C F0 3C F4 3C F8 3C FC 3C 00 3D 04 3D 08 3D 0C 3D 10 }

    condition:
        2 of ($key*) or
        ($data1 and any of ($seq*)) or
        3 of ($seq*)
}