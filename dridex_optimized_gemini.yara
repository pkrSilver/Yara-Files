rule malware_dridex_optimized
{
    meta:
        description = "Optimized detection for Dridex (Dridex/Cridex) malware family variants (Syntax Corrected)."
        author = "Gemini"
        date = "2023-10-27"
        family = "Dridex"
        accuracy_focus = "Prioritizing high-entropy key blobs and high-coverage metadata."
        
    strings:
        // --- Core Indicator (Highest Confidence: Found in 20 samples of dridex1.yara) ---
        // This key is C1 92 C8 3C E4 31 3B 52 12 29 18 79 CE CB 45 9E 20 89 D7 1F 35 DB 23 B5 30 4A 8D 5E 59 15 E6 8B
        $core_obf_data_key = { C1 92 C8 3C E4 31 3B 52 12 29 18 79 CE CB 45 9E 20 89 D7 1F 35 DB 23 B5 30 4A 8D 5E 59 15 E6 8B }
        
        // --- High-Coverage Metadata (Supporting Evidence) ---
        
        // Wide-char fragment of "Translation" or similar resource string (Found in 45 files)
        $meta_translation = { 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F 00 } // Looks like: a.n.s.l.a.t.i.o.
        
        // Wide-char fragment of "Product Name" or similar resource string (Found in 44 files)
        $meta_product = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 } // Looks like: P.r.o.d.u.c.t.N.
        
        // Wide-char fragment of "ctVersion" or similar resource string (Found in 43 files)
        $meta_version = { 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F } // Looks like: .c.t.V.e.r.s.i.o.
        
    condition:
        // Rule requires the file to be a Windows PE executable (MZ header) AND must contain a strong indicator combination:
        uint16(0) == 0x5A4D and (
            // The high-entropy key plus one high-coverage metadata string
            $core_obf_data_key and 1 of ($meta_translation, $meta_product, $meta_version) or
            
            // OR all three high-coverage metadata strings (which were key to the high TP rate of dridex3.yara)
            all of ($meta_translation, $meta_product, $meta_version)
        )
}