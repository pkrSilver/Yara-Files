rule Mirai_Malware
{
    meta:
        description = "Detects Mirai malware based on concatenated error strings and unique byte patterns"
        author = "Optimized from AutoYARA rules"
        family = "Mirai Botnet"
        date = "2025-12-15"
        reference = "Internal analysis of 50 samples"

    strings:
        // Concatenated error strings from libc, common in statically linked Mirai binaries
        $x1 = { 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 } // "otocol family not supportedAddr"
        $x2 = { 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 65 73 73 20 66 61 6D } // "family not supportedAddress fam"
        $x3 = "dress family not supported by pr" ascii // Partial address family error
        $x4 = { 00 50 72 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 65 73 73 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 20 62 79 20 70 } // Full "Protocol family not supportedAddress family not supported by p"
        $x5 = { 00 4F 70 65 72 61 74 69 6F 6E 20 6E 6F 74 20 70 65 72 6D 69 74 74 65 64 00 4E 6F 20 73 75 63 68 20 66 69 6C 65 20 6F 72 20 64 69 72 65 63 74 6F 72 79 00 4E 6F 20 73 75 63 68 20 70 72 6F 63 65 } // "Operation not permittedNo such file or directoryNo such proce"
        $x6 = { 00 49 6E 76 61 6C 69 64 20 65 78 63 68 61 6E 67 65 00 49 6E 76 61 6C 69 64 20 72 65 71 75 65 73 74 20 64 65 73 63 72 69 70 74 6F 72 00 45 78 63 68 61 6E 67 65 20 66 75 6C 6C 00 4E 6F 20 61 6E } // "Invalid exchangeInvalid request descriptorExchange fullNo an"
        $x7 = { 6F 20 6D 61 6E 79 20 6F 70 65 6E 20 66 69 6C 65 73 00 49 6E 61 70 70 72 6F 70 72 69 61 74 65 20 69 6F 63 74 6C 20 66 6F 72 20 64 65 76 69 63 65 00 54 65 78 74 20 66 69 6C 65 20 62 75 73 79 00 } // "o many open filesInappropriate ioctl for deviceText file busy"
        // High-entropy byte sequence, possibly XOR key or random table
        $x8 = { 00 00 00 00 00 00 00 05 CA 7F 16 9C 11 F9 89 00 00 00 00 02 9D 74 8B 45 AA 7B EF B9 9E FE AD 08 19 BA CF 41 E0 16 A2 32 6C F3 CF F4 8E 3C 44 83 C8 8D 51 45 6F 90 95 23 3E 00 97 2B 1C 71 B2 4E }

    condition:
        5 of them
}