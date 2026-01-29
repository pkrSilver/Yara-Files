rule malware_redline_optimized
{
    meta:
        description = "Optimized detection for Redline Stealer based on AutoYara analysis"
        author = "Gemini"
        date = "2023-10-27"
        hash1 = "redline_sample_set"

    strings:
        // --- Strong Indicators (High Specificity/Entropy) ---
        
        // Unique byte sequence (High Entropy: 5.0) - Likely obfuscated data or table
        $strong_bytes_01 = { 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C }
        
        // Unique byte sequence (High Entropy: ~4.3)
        $strong_bytes_02 = { 00 00 0D 88 84 81 FF F7 F5 F3 FF FB F9 F6 FF D1 BD BC FF 8C 95 50 FF 8B 97 51 FF 89 9A 53 FF 87 }
        
        // High entropy byte pattern found in ~26 files
        $strong_bytes_03 = { A3 A4 A5 0D 0E 5F 0B A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7 E2 01 02 04 05 06 00 }
        
        // Specific GUIDs found in redline1 (often associated with TypeLib or Interface IDs in the malware)
        $guid_01 = "Id=\"{1f676c76-8" ascii
        $guid_02 = "=\"{35138b9a-5d96" ascii

        // --- Moderate Indicators (Suspicious Artifacts) ---
        
        // Suspicious concatenated strings/typos often found in Redline unpacked memory
        $susp_str_01 = "ributeCompilationRelaxationsAtt" ascii
        $susp_str_02 = "Wow64RevertWow64FsRedirection" ascii // API often used for injection
        $susp_str_03 = "rowsableAttributeComVisibleAttr" ascii
        $susp_str_04 = "urceExLoadImageWMonitorF" ascii
        
        // XML Assembly Identity (Generic but helpful in combination)
        $xml_ident = "n=\"1.0\">\r\n  <assemblyIdentity ve" ascii

        // Obfuscation/Packing artifacts
        $confuser_bytes = { 40 24 C1 E8 1F F7 D0 83 E0 01 C7 45 FC FE FF FF FF 8B 4D F0 }
        
        // --- Contextual Indicators (Weaker on their own, useful for weight) ---
        
        $dotnet_culture = "ersion=4.0.0.0, Culture=neutral," ascii
        $resource_builder = "glyTypedResourceBuilder16.0.0.0" ascii
        $crypto_str = "gyptian_HieroglyphsEthiopicGeo" ascii // Specific weird string from redline3
        
    condition:
        uint16(0) == 0x5A4D and (
            // Require 1 strong unique byte sequence OR
            (1 of ($strong_bytes_*)) or
            // A combination of GUIDs and specific strings OR
            (1 of ($guid_*) and 2 of ($susp_str_*)) or
            // A cluster of suspicious strings and moderate indicators
            (4 of ($susp_str_*, $xml_ident, $confuser_bytes, $dotnet_culture, $resource_builder, $crypto_str))
        )
}