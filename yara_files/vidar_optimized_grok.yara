rule Vidar_Malware
{
    meta:
        description = "Detects Vidar stealer malware based on unique strings and embedded patterns"
        author = "Optimized from AutoYARA and public analyses (eSentire, Fumik0, eln0ty)"
        family = "Vidar Stealer"
        date = "2025-12-15"
        reference = "Internal analysis of 50 samples and public reports"

    strings:
        // Specific strings from stealer functionality
        $s1 = "Version: %s" ascii wide
        $s2 = "Password: %s" ascii wide
        $s3 = "Soft: The Bat!" ascii wide
        $s4 = "files\\Soft\\Authy" ascii wide
        $s5 = "%s\\%s\\Local Storage\\leveldb" ascii
        $s6 = "\\Autofill\\%s_%s.txt" ascii
        $s7 = "\\CC\\%s_%s.txt" ascii
        $s8 = "Exodus\\exodus.wallet" ascii

        // DLL dependencies often embedded or loaded
        $dll1 = "nss3.dll" ascii wide
        $dll2 = "msvcp140.dll" ascii wide
        $dll3 = "mozglue.dll" ascii wide
        $dll4 = "freebl3.dll" ascii wide
        $dll5 = "vcruntime140.dll" ascii wide
        $dll6 = "softokn3.dll" ascii wide

        // Embedded ZIP header for DLLs (from eSentire)
        $zip_header = {50 4B 03 04 14 00 00 00 08 00 24 56 25 55 2B 6D 5C 08 39 7C 05}

        // Constant hex string common in variants
        $hex_const = "1BEF0A57BE110FD467A" ascii

        // High-entropy pattern from AutoYARA (certificate-like, found in 15 files)
        $cert_pattern = { 4C 30 17 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 09 03 01 00 A0 04 A2 02 80 00 30 31 30 0D 06 09 }

    condition:
        uint16(0) == 0x5A4D and // MZ header
        (
            $hex_const or
            $zip_header or
            $cert_pattern or
            4 of ($s*) or
            all of ($dll*)
        )
}