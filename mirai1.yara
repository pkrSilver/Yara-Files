rule malware_samples_mirai
{
	//Input TP Rate:
	//30/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.003928031846025 Found in 29 files
		$x0 = { 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 } //This might be a string? Looks like:otocol family not supportedAddr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.765319531114783 Found in 23 files
		$x1 = "oo many references: cannot splic" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.054229296672174 Found in 26 files
		$x2 = { 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 65 73 73 20 66 61 6D } //This might be a string? Looks like:family not supportedAddress fam
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.878928031846024 Found in 30 files
		$x3 = "dress family not supported by pr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x4 = { 0F 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 17 00 18 00 19 00 1A 00 1B 00 1C 00 1D 00 1E 00 } 

		condition:
(3 of ($x0,$x1,$x2,$x3,$x4) )}