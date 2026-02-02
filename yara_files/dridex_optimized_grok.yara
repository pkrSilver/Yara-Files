rule Dridex_Malware
{
    meta:
        description = "Detects Dridex malware based on API hashing code patterns and encryption keys"
        author = "Optimized from AutoYARA and public rules (SentinelOne, etc.)"
        family = "Dridex Banker"
        date = "2025-12-15"
        reference = "Internal analysis of 50 samples and SentinelOne research"

    strings:
        // API hashing function from SentinelOne YARA rule for Dridex family
        $api_hash = { 5? 5? 8B FA 8B ?? 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 81 ?? ?? ?? ?? ?? 7? ?? }
        
        // High-entropy byte sequence from AutoYARA, likely encryption table or key (found in 20 samples)
        $key1 = { C1 92 C8 3C E4 31 3B 52 12 29 18 79 CE CB 45 9E 20 89 D7 1F 35 DB 23 B5 30 4A 8D 5E 59 15 E6 8B }
        
        // Another pattern from AutoYARA, potential loader string concatenation (found in 10 samples)
        $str1 = { 6C 00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32 00 4C 64 72 47 65 74 50 72 6F 63 65 64 75 72 }
        
        // ADVAPI32 string pattern (found in 9 samples)
        $str2 = { 53 65 72 76 69 63 65 44 69 73 70 6C 61 79 4E 61 6D 65 57 00 00 41 44 56 41 50 49 33 32 2E 64 6C }

        // Specific byte pattern from dridex2/3 (found in 31 samples, potential unique identifier)
        $id_pattern = { 39 E3 AB DE C0 DE C0 3F 00 00 00 00 00 00 00 00 }

    condition:
        $api_hash or
        2 of ($key*, $str*) or
        $id_pattern
}