rule Formbook_Malware
{
    meta:
        description = "Detects Formbook malware based on unique code patterns and high-entropy data sequences"
        author = "Optimized from AutoYARA rules and public sources"
        family = "Formbook Stealer"
        date = "2025-12-15"
        reference = "Internal analysis of 50 samples and Elastic Security Labs"

    strings:
        // High-entropy byte sequence from AutoYARA, likely encryption table or key
        $key1 = { 7B A0 5C B3 2B C0 7E 18 CC 94 DD 66 BB 04 AB 8D DF E8 55 69 48 29 D6 B7 48 A1 61 54 AC CE 56 A2 2C A9 80 4B BA 50 F0 D8 5F 47 84 1A B1 5D BF 59 2C AA D2 E1 2E C6 32 8C 9B 60 1C 9D 78 39 AF BD }
        // Part of long high-entropy sequence from formbook3.yara
        $key2 = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 36 4D A8 FF 73 24 A7 3C F6 7A 12 F1 67 AC C1 93 E7 6B 43 CA 52 A6 AD 00 00 E1 BB 3A 21 A5 29 E3 EC E7 0B 98 2E 40 BD E1 9A DE 80 46 B1 9D 6B 3B 21 D4 B1 D6 75 3A C8 3D C6 D0 33 F7 14 AF CB 17 A2 94 01 8D 13 88 FE 64 95 61 E7 B6 4D 62 F8 00 00 6C FE 74 84 6A 78 49 F1 B5 91 05 38 EE 76 1E F9 D2 72 0B 54 8D 83 9D 74 78 48 10 8D 21 E7 DC 29 39 38 4F B5 FD 09 2C E4 58 4F 67 3B 4D 6D 98 3D 98 98 41 A4 FC 46 50 }

        // Code patterns from Elastic Security
        $code1 = { 3C 30 50 4F 53 74 09 40 }
        $code2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
        $code3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
        $code4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }

        // Additional code sequences from malware analysis
        $seq1 = { 33 DB 53 FF 75 FC FF 75 F8 57 E8 84 FD FF FF }
        $seq2 = { FF 50 FF B5 3C FD FF FF 8D 85 68 FE FF FF 50 E8 4C 0F }

    condition:
        any of ($key*) or
        2 of ($code*) or
        all of ($seq*)
}