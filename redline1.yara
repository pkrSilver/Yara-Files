rule malware_samples
{
	//Input TP Rate:
	//28/49
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 31 files
		$x0 = { 77 00 69 00 74 00 68 00 20 00 74 00 68 00 65 00 } //This might be a string? Looks like:with the
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 24 files
		$x1 = { 48 58 66 3B D0 74 05 8D 46 FF 89 07 5F 5E 5B 5D } //This might be a string? Looks like:HXf;tF_^[]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 29 files
		$x2 = { 00 C0 02 47 6C 6F 62 61 6C 4D 65 6D 6F 72 79 53 } //This might be a string? Looks like:GlobalMemoryS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.186278124459133 Found in 21 files
		$x3 = { 03 FF FF FF FF FF FF FF FF FF FF FF FF 28 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 31 files
		$x4 = { 00 74 00 69 00 61 00 6C 00 69 00 7A 00 65 00 64 } //This might be a string? Looks like:tialized
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 27 files
		$x5 = { 00 73 00 65 00 63 00 74 00 69 00 6F 00 6E 00 20 } //This might be a string? Looks like:section 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 32 files
		$x6 = "WaitForSingleObj" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 30 files
		$x7 = { 02 47 65 74 54 65 6D 70 46 69 6C 65 4E 61 6D 65 } //This might be a string? Looks like:GetTempFileName
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 27 files
		$x8 = { 83 C4 0C 5F 5E DD 45 8A E9 11 FF FF FF 55 8B EC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 32 files
		$x9 = "andledExceptionF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 31 files
		$x10 = "stTokenPrivilege" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 29 files
		$x11 = { 20 49 64 3D 22 7B 31 66 36 37 36 63 37 36 2D 38 } //This might be a string? Looks like: Id="{1f676c76-8
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 28 files
		$x12 = { E6 FB 25 78 C8 E2 13 F9 7D 1D ED DD 71 00 B0 55 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 30 files
		$x13 = { 3D 22 7B 33 35 31 33 38 62 39 61 2D 35 64 39 36 } //This might be a string? Looks like:="{35138b9a-5d96
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 30 files
		$x14 = { FF FF 33 C0 8B 4D F0 64 89 0D 00 00 00 00 59 5F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 31 files
		$x15 = { 00 00 00 00 00 00 20 00 00 60 2E 72 64 61 74 61 } //This might be a string? Looks like: `.rdata
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 20 files
		$x16 = { 26 00 00 00 0D 8B 86 84 F6 F7 F5 F3 FF F8 F9 FA } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 33 files
		$x17 = { 43 75 72 72 65 6E 74 54 68 72 65 61 64 49 64 00 } //This might be a string? Looks like:CurrentThreadId
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 29 files
		$x18 = { 20 00 69 00 74 00 73 00 65 00 6C 00 66 00 2E 00 } //This might be a string? Looks like: itself.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 30 files
		$x19 = { 00 55 00 6E 00 61 00 62 00 6C 00 65 00 20 00 74 } //This might be a string? Looks like:Unable t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 30 files
		$x20 = { 6F 43 72 65 61 74 65 49 6E 73 74 61 6E 63 65 00 } //This might be a string? Looks like:oCreateInstance
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 28 files
		$x21 = { 65 00 20 00 63 00 6F 00 6E 00 73 00 74 00 72 00 } //This might be a string? Looks like:e constr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 27 files
		$x22 = "w64DisableWow64F" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 28 files
		$x23 = { 72 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 } //This might be a string? Looks like:r thread
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 26 files
		$x24 = { 63 79 00 4E 01 46 69 6E 64 52 65 73 6F 75 72 63 } //This might be a string? Looks like:cyNFindResourc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 27 files
		$x25 = { 41 56 74 79 70 65 5F 69 6E 66 6F 40 40 00 00 00 } //This might be a string? Looks like:AVtype_info@@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 29 files
		$x26 = { 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A 9B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 25 files
		$x27 = { 7F 07 C6 85 70 FF FF FF 01 0A C9 C3 0A C9 74 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 30 files
		$x28 = { 00 74 00 69 00 61 00 6C 00 69 00 7A 00 65 00 20 } //This might be a string? Looks like:tialize 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 26 files
		$x29 = { 0C FA 3F 32 D5 1C 5D 49 59 93 BC 33 2D 4A EC 9B } //This might be a string? Looks like:?2]IY3-J
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 18 files
		$x30 = { 31 F9 FF 5F 5E 33 C0 5B 8B E5 5D C2 08 00 55 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.077819531114783 Found in 23 files
		$x31 = { 00 01 00 20 00 A8 25 00 00 09 00 20 20 00 00 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 27 files
		$x32 = { C4 53 3B 75 44 CD 14 BE 9A AF 3F DE 67 BA 94 39 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 30 files
		$x33 = { 43 68 61 72 54 6F 4D 75 6C 74 69 42 79 74 65 00 } //This might be a string? Looks like:CharToMultiByte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 29 files
		$x34 = { 00 69 00 61 00 6C 00 69 00 7A 00 65 00 64 00 20 } //This might be a string? Looks like:ialized 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 27 files
		$x35 = { FE 72 09 8B 48 08 03 CE 3B F9 72 0A 42 83 C0 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 28 files
		$x36 = { 00 46 00 75 00 6E 00 63 00 74 00 69 00 6F 00 6E } //This might be a string? Looks like:Function
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 18 files
		$x37 = { 00 55 8B EC 83 E4 F8 83 EC 4C 8B 4D 0C 53 56 57 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 29 files
		$x38 = { 20 00 61 00 70 00 70 00 6C 00 69 00 63 00 61 00 } //This might be a string? Looks like: applica
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1774212838293647 Found in 21 files
		$x39 = { 41 00 00 01 00 01 00 10 10 10 00 01 00 04 00 28 } 

		condition:
(25 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39) )}