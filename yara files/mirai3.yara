rule malware_samples_mirai
{
	//Input TP Rate:
	//12/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.003928031846025 Found in 29 files
		$x0 = { 6F 74 6F 63 6F 6C 20 66 61 6D 69 6C 79 20 6E 6F 74 20 73 75 70 70 6F 72 74 65 64 00 41 64 64 72 } //This might be a string? Looks like:otocol family not supportedAddr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x1 = { 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3A 00 3B 00 3C 00 3D 00 3E 00 3F } //This might be a string? Looks like:0123456789:;<=>?
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.765319531114783 Found in 23 files
		$x2 = "oo many references: cannot splic" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 18 files
		$x3 = { 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C } //This might be a string? Looks like: !"#$%&'()*+,-./0123456789:;<
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x4 = { 0F 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 17 00 18 00 19 00 1A 00 1B 00 1C 00 1D 00 1E 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.878928031846024 Found in 30 files
		$x5 = "dress family not supported by pr" ascii

		condition:
(6 of ($x0,$x1,$x2,$x3,$x4,$x5) )}