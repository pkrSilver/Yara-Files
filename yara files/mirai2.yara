rule malware_samples_mirai
{
	//Input TP Rate:
	//19/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.216328470024671 Found in 19 files
		$x0 = { 6F 20 6D 61 6E 79 20 6F 70 65 6E 20 66 69 6C 65 73 00 49 6E 61 70 70 72 6F 70 72 69 61 74 65 20 69 6F 63 74 6C 20 66 6F 72 20 64 65 76 69 63 65 00 54 65 78 74 20 66 69 6C 65 20 62 75 73 79 00 } //This might be a string? Looks like:o many open filesInappropriate ioctl for deviceText file busy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 19 files
		$x1 = { 77 00 78 00 79 00 7A 00 7B 00 7C 00 7D 00 7E 00 7F 00 80 00 81 00 82 00 83 00 84 00 85 00 86 00 87 00 88 00 89 00 8A 00 8B 00 8C 00 8D 00 8E 00 8F 00 90 00 91 00 92 00 93 00 94 00 95 00 96 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.439835060327363 Found in 21 files
		$x2 = { 04 C0 04 C0 04 C0 04 C0 04 D8 08 D8 08 D8 08 D8 08 D8 08 D8 08 D8 08 D8 08 D8 08 D8 08 C0 04 C0 04 C0 04 C0 04 C0 04 C0 04 C0 04 D5 08 D5 08 D5 08 D5 08 D5 08 D5 08 C5 08 C5 08 C5 08 C5 08 C5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.138508938909887 Found in 26 files
		$x3 = { 00 50 72 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 65 73 73 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 20 62 79 20 70 } //This might be a string? Looks like:Protocol family not supportedAddress family not supported by p
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 21 files
		$x4 = { 84 00 85 00 86 00 87 00 88 00 89 00 8A 00 8B 00 8C 00 8D 00 8E 00 8F 00 90 00 91 00 92 00 93 00 94 00 95 00 96 00 97 00 98 00 99 00 9A 00 9B 00 9C 00 9D 00 9E 00 9F 00 A0 00 A1 00 A2 00 A3 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.065774219659049 Found in 29 files
		$x5 = { 00 4F 70 65 72 61 74 69 6F 6E 20 6E 6F 74 20 70 65 72 6D 69 74 74 65 64 00 4E 6F 20 73 75 63 68 20 66 69 6C 65 20 6F 72 20 64 69 72 65 63 74 6F 72 79 00 4E 6F 20 73 75 63 68 20 70 72 6F 63 65 } //This might be a string? Looks like:Operation not permittedNo such file or directoryNo such proce
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.234069531114783 Found in 17 files
		$x6 = { 00 00 00 00 00 00 00 05 CA 7F 16 9C 11 F9 89 00 00 00 00 02 9D 74 8B 45 AA 7B EF B9 9E FE AD 08 19 BA CF 41 E0 16 A2 32 6C F3 CF F4 8E 3C 44 83 C8 8D 51 45 6F 90 95 23 3E 00 97 2B 1C 71 B2 4E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.38502739943295 Found in 22 files
		$x7 = { 00 49 6E 76 61 6C 69 64 20 65 78 63 68 61 6E 67 65 00 49 6E 76 61 6C 69 64 20 72 65 71 75 65 73 74 20 64 65 73 63 72 69 70 74 6F 72 00 45 78 63 68 61 6E 67 65 20 66 75 6C 6C 00 4E 6F 20 61 6E } //This might be a string? Looks like:Invalid exchangeInvalid request descriptorExchange fullNo an

		condition:
(6 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7) )}