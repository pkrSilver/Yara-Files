rule Redline_Malware
{
    meta:
        description = "Detects Redline malware based on unique code and data patterns"
        author = "Optimized from AutoYARA rules"
        family = "Redline Stealer"
        date = "2025-12-15"
        reference = "Internal analysis of 49 samples"

    strings:
        // High-entropy byte sequences unique to Redline packer/obfuscation
        $x1 = { CC 80 F9 40 73 15 80 F9 20 73 06 0F AD D0 D3 EA C3 8B C2 33 D2 80 E1 1F D3 E8 C3 33 C0 33 D2 C3 }
        $x2 = { 40 24 C1 E8 1F F7 D0 83 E0 01 C7 45 FC FE FF FF FF 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B 8B }
        $x3 = { 65 E8 FF 75 F8 8B 45 FC C7 45 FC FE FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 }
        $x4 = { D5 EF 89 85 B1 71 1F B5 B6 06 A5 E4 BF 9F 33 D4 B8 E8 A2 C9 07 78 34 F9 00 0F 8E A8 09 96 18 98 }
        $x5 = { A3 A4 A5 0D 0E 5F 0B A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7 E2 01 02 04 05 06 00 }
        $x6 = { F9 D0 C1 8A C1 24 0F D7 0F BE C0 81 E1 04 04 00 00 8B DA 03 D8 83 C3 10 FF 23 80 7A 0E 05 75 11 }
        $x7 = { 3B 54 24 14 77 08 72 07 3B 44 24 10 76 01 4E 33 D2 8B C6 4F 75 07 F7 DA F7 D8 83 DA 00 5B 5E 5F }
        $x8 = { 56 57 8B 48 3C 03 C8 0F B7 41 14 0F B7 59 06 83 C0 18 03 C1 85 DB 74 1B 8B 7D 0C 8B 70 0C 3B FE }
        $x9 = { 0D 84 D2 74 D4 5E 33 C0 5B 59 5D C2 04 00 B2 01 EB EF 55 8B EC 83 EC 68 53 56 57 8D 4D 9C E8 CC }
        $x10 = { C1 24 0F D7 D0 E4 D0 E4 0A C4 0F BE C0 81 E1 04 04 00 00 8B DA 03 D8 83 C3 10 FF 23 E8 C1 00 00 }

    condition:
        8 of them
}