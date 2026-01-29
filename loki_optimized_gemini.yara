rule malware_loki_optimized
{
    meta:
        description = "Optimized detection for Loki (LokiBot) stealer variants."
        author = "Gemini"
        date = "2023-10-27"
        family = "Loki"
        accuracy_focus = "Minimizing FPs by requiring high-entropy artifacts."

    strings:
        // --- Core Indicators (Highest Confidence) ---
        
        // Primary high-entropy key/data block (Found in 29 samples)
        $core_obf_key = { 24 E9 0B B1 87 7C 6F 2F 11 4C 68 58 AB 1D 61 C1 3D 2D 66 B6 90 41 DC 76 06 71 DB 01 BC 20 D2 98 } 
        
        // Secondary high-entropy key/data block (Found in 30 samples in files 2 & 3)
        $core_comp_key = { 67 07 72 13 57 00 05 82 4A BF 95 14 7A B8 E2 AE 2B B1 7B 38 1B B6 0C 9B 8E D2 92 0D BE D5 E5 B7 }
        
        // --- System Artifacts (High Coverage, Loki-specific path) ---
        
        // Fragment of a wide-character Windows Registry path, e.g., "Software\Microsoft\Windows..." (Found in 24 samples)
        $art_reg_path = { 61 00 72 00 65 00 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 57 00 69 00 } // Looks like: are\Microsoft\Wi

        // --- Metadata/Data Structure Artifacts ---
        
        // Wide-char sequential ASCII fragment (Found in 24 samples)
        $art_wide_ascii = { 00 45 00 46 00 47 00 48 00 49 00 4A 00 4B 00 4C 00 4D 00 4E 00 4F 00 50 00 51 00 52 00 53 00 54 } // Looks like: EFGHIJKLMNOPQRST
        
        // Manifest XML tag (Found in 18 samples in file 3)
        $art_manifest_tag = { 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 } // Looks like: <trustInfo xmlns="urn:schemas-mi
        
    condition:
        // Must be a Windows executable (MZ header) AND must contain the primary obfuscated key AND at least two other specific artifacts.
        uint16(0) == 0x5A4D and (
            $core_obf_key and 
            2 of ($core_comp_key, $art_reg_path, $art_wide_ascii, $art_manifest_tag)
        )
}