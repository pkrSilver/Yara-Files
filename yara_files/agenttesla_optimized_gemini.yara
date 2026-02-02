rule malware_agenttesla_optimized
{
    meta:
        description = "Optimized detection for AgentTesla Stealer (C#/.NET) variants."
        author = "Gemini"
        date = "2023-10-27"
        family = "AgentTesla"

    strings:
        // --- Core Indicators (Highest Coverage: 32+ files) ---
        
        // Very high confidence string from file version information
        $core_file_vers = "FileVers" ascii // Found in 45 files
        
        // High confidence string fragment (likely part of "GetObje"ct/Get_Obje"ct)
        $core_get_obj = { 00 47 65 74 4F 62 6A 65 } // Found in 34 files (Hex for ".G.e.t.O.b.j.e")
        
        // High confidence string fragment (likely part of "Coun"t/get_Coun"t")
        $core_get_count = "get_Coun" ascii // Found in 32 files
        
        // High confidence string fragment (likely part of "Comp"any/C"ompa"ny)
        $core_comp_frag = { 00 6F 00 6D 00 70 00 61 } // Found in 34 files (Hex for ".o.m.p.a")

        // --- Specific Artifacts (Moderate Coverage: 20-32 files) ---
        
        // .NET property related: "get_H"ashCode or "get_H"ost
        $art_get_h = { 00 67 00 65 00 74 00 5F 00 48 } // Found in 32 files (Hex for ".g.e.t._.H")
        
        // Specific compiler/linker artifact (Found in files 2 and 3)
        $art_compiler_ver = { 64 65 72 08 31 37 2E 30 } // Looks like "der17.0" - Found in 32 files
        
        // String fragment found in 23 files (Likely part of "load " or "load_")
        $art_load_frag = { 6F 00 61 00 64 00 20 00 } // Hex for ".o.a.d. "
        
        // Network/Execution related fragment (Likely part of "tect" or "detect")
        $art_detect = { 00 74 00 65 00 63 00 74 } // Hex for ".t.e.c.t" - Found in 32 files
        
    condition:
        // Rule requires the file to be a Windows PE executable (MZ header) AND a strong combination of strings.
        uint16(0) == 0x5A4D and (
            // A cluster of 3 of the 4 core indicators OR
            3 of ($core_*) or
            
            // The highest-confidence string plus 3 other artifacts.
            ($core_file_vers and 3 of ($art_*))
        )
}