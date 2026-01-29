rule malware_mirai_optimized
{
    meta:
        description = "Optimized detection for Mirai Botnet based on AutoYara analysis of static build artifacts"
        author = "Gemini"
        date = "2023-10-27"
        hash1 = "mirai_sample_set"

    strings:
        // --- Strong Indicators (Specific High Entropy) ---
        // Unique byte sequence found in 17 files - likely a crypto constant or encoded config
        $strong_bytes_01 = { 00 00 00 00 00 00 00 05 CA 7F 16 9C 11 F9 89 00 00 00 00 02 9D 74 8B 45 AA 7B EF B9 9E FE AD 08 }

        // --- Structural Indicators (Concatenated Library Strings) ---
        // These strings are standard errors, but their *concatenation* fingerprints the 
        // specific static library (likely uClibc) and build configuration used by Mirai.
        
        // "o many open filesInappropriate ioctl for deviceText file busy"
        $concat_err_1 = { 6F 20 6D 61 6E 79 20 6F 70 65 6E 20 66 69 6C 65 73 00 49 6E 61 70 70 72 6F 70 72 69 61 74 65 20 69 6F 63 74 6C 20 66 6F 72 20 64 65 76 69 63 65 00 54 65 78 74 20 66 69 6C 65 20 62 75 73 79 00 }
        
        // "Protocol family not supportedAddress family not supported by p"
        $concat_err_2 = { 00 50 72 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 65 73 73 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 20 62 79 20 70 }
        
        // "Operation not permittedNo such file or directoryNo such proce"
        $concat_err_3 = { 00 4F 70 65 72 61 74 69 6F 6E 20 6E 6F 74 20 70 65 72 6D 69 74 74 65 64 00 4E 6F 20 73 75 63 68 20 66 69 6C 65 20 6F 72 20 64 69 72 65 63 74 6F 72 79 00 4E 6F 20 73 75 63 68 20 70 72 6F 63 65 }
        
        // "Invalid exchangeInvalid request descriptorExchange fullNo an"
        $concat_err_4 = { 00 49 6E 76 61 6C 69 64 20 65 78 63 68 61 6E 67 65 00 49 6E 76 61 6C 69 64 20 72 65 71 75 65 73 74 20 64 65 73 63 72 69 70 74 6F 72 00 45 78 63 68 61 6E 67 65 20 66 75 6C 6C 00 4E 6F 20 61 6E }

        // "oo many references: cannot splic" - Retained as a secondary indicator
        $err_splice = "oo many references: cannot splic" ascii

    condition:
        // Detection Logic:
        // 1. The strong unique byte sequence alone is sufficient.
        // 2. OR, a cluster of 3+ concatenated string blocks, confirming the specific static library structure.
        
        $strong_bytes_01 or
        3 of ($concat_err_*) or
        (2 of ($concat_err_*) and $err_splice)
}