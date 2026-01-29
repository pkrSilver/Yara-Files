rule dridex3
{
	//Input TP Rate:
	//43/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 43 files
		$x0 = { 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F } //This might be a string? Looks like:ctVersio
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 45 files
		$x1 = { 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F 00 } //This might be a string? Looks like:anslatio
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 44 files
		$x2 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 } //This might be a string? Looks like:ProductN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 31 files
		$x3 = { 39 E3 AB DE C0 DE C0 3F 00 00 00 00 00 00 00 00 } 

		condition:
(3 of ($x0,$x1,$x2,$x3) )}