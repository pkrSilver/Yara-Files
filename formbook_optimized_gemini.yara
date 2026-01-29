rule malware_formbook_optimized
{
    meta:
        description = "Optimized detection for Formbook Stealer variants (prioritizes unique API sequences and data blobs)."
        author = "Gemini"
        date = "2023-10-27"
        family = "Formbook"
        
    strings:
        // --- Tier 1: Crucial Indicators (High Specificity) ---
        
        // Extensive block of specific Windows API names (ExitWindowsEx, mouse_event, LoadImageW, PeekMessageW, etc.)
        // Found in 11 files (formbook3.yara) - Extremely high confidence indicator.
        $core_api_set = { 00 45 78 69 74 57 69 6E 64 6F 77 73 45 78 00 31 03 6D 6F 75 73 65 5F 65 76 65 6E 74 00 EF 01 4C 6F 61 64 49 6D 61 67 65 57 00 00 19 02 4D 6F 6E 69 74 6F 72 46 72 6F 6D 52 65 63 74 00 2D 00 43 68 61 72 4C 6F 77 65 72 42 75 66 66 57 00 00 08 03 55 6E 72 65 67 69 73 74 65 72 48 6F 74 4B 65 79 00 00 38 01 47 65 74 49 6E 70 75 74 53 74 61 74 65 00 33 02 50 65 65 6B 4D 65 73 73 61 67 65 57 00 00 FC 02 54 72 61 6E 73 6C 61 74 65 4D 65 73 73 61 67 65 00 00 AF 00 44 69 73 70 61 74 63 68 4D 65 73 73 61 67 65 57 00 00 FD 01 }
        
        // High-entropy data/obfuscation block (Found in 17 files, formbook1.yara)
        $core_obf_data = { 7B A0 5C B3 2B C0 7E 18 CC 94 DD 66 BB 04 AB 8D DF E8 55 69 48 29 D6 B7 48 A1 61 54 AC CE 56 A2 2C A9 80 4B BA 50 F0 D8 5F 47 84 1A B1 5D BF 59 2C AA D2 E1 2E C6 32 8C 9B 60 1C 9D 78 39 AF BD } 

        // --- Tier 2: Supporting Artifacts (High Coverage/Specific Functionality) ---
        
        // API chain: MultiByteToWideChar, MulDiv, GetVersionExW, IsWow64Process (Found in 11 files, formbook1.yara)
        $art_api_chain = { 49 64 00 00 67 03 4D 75 6C 74 69 42 79 74 65 54 6F 57 69 64 65 43 68 61 72 00 66 03 4D 75 6C 44 69 76 00 00 A4 02 47 65 74 56 65 72 73 69 6F 6E 45 78 57 00 0E 03 49 73 57 6F 77 36 34 50 72 6F }
        
        // Metadata string: "FileVers" (Very high coverage in Formbook samples: 42 files, formbook2.yara)
        $art_file_vers = "FileVers" ascii
        
        // Common .NET object getter fragment: ".GetObje"ct (Found in 32 files, formbook2.yara)
        $art_get_obj = { 00 47 65 74 4F 62 6A 65 } 
        
    condition:
        // Rule requires the file to be a Windows PE executable (MZ header) AND a strong combination of strings.
        uint16(0) == 0x5A4D and (
            // EITHER one of the highly unique Tier 1 strings is present
            $core_api_set or $core_obf_data or 
            
            // OR a combination of three supporting Tier 2 strings are present.
            3 of ($art_api_chain, $art_file_vers, $art_get_obj)
        )
}