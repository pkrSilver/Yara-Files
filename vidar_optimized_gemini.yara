rule malware_vidar_optimized
{
    meta:
        description = "Optimized detection for Vidar Stealer variants."
        author = "Gemini"
        date = "2023-10-27"
        family = "Vidar"
        
    strings:
        // --- Core Indicators (Highest Specificity) ---
        
        // Highly specific sequential ASCII string (Numbers and uppercase letters). Found in 32 files.
        $core_ascii_seq = "56789:;<=>?@ABCDEFGHIJKLMNOPQRST" ascii 
        
        // Repeated instruction/data block (Found in 11 files in vidar1 and vidar2)
        $core_code_artifact = { F8 AC 08 AD 10 AD 20 AD 28 AD 38 AD 40 AD 50 AD 58 AD 68 AD 70 AD 80 AD 88 AD 98 AD A0 AD B0 AD } 
        
        // --- Supporting Artifacts (High Coverage/Functionality) ---
        
        // Console/String formatting API fragment (Found in 7 files)
        $art_console_write = { 2A 46 44 29 2E 77 72 69 74 65 43 6F 6E 73 6F 6C 65 00 75 6E 69 63 6F 64 65 2F 75 74 66 38 2E 46 } // Looks like: *FD).writeConsoleunicode/utf8.F
        
        // Common C++ exception/STL string (Found in 30 files in vidar3)
        $art_exception_std = "?AVexception@std" ascii
        
        // Performance/Timing related ASCII fragment (Found in 39 files in vidar3)
        $art_perf_freq = "formanceFrequenc" ascii
        
    condition:
        // Rule requires the file to contain the primary unique string AND at least two other specific artifacts.
        $core_ascii_seq and 2 of ($core_code_artifact, $art_console_write, $art_exception_std, $art_perf_freq)
}