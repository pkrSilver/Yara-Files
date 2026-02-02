rule dridex1
{
	//Input TP Rate:
	//31/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 20 files
		$x5 = { C1 92 C8 3C E4 31 3B 52 12 29 18 79 CE CB 45 9E 20 89 D7 1F 35 DB 23 B5 30 4A 8D 5E 59 15 E6 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x12 = { 1D 00 1E 00 1F 00 20 00 21 00 22 00 23 00 24 00 25 00 26 00 27 00 28 00 29 00 2A 00 2B 00 2C 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6014097655573916 Found in 44 files
		$x7 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 } //This might be a string? Looks like:OriginalFilename
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x14 = { 22 00 23 00 24 00 25 00 26 00 27 00 28 00 29 00 2A 00 2B 00 2C 00 2D 00 2E 00 2F 00 30 00 31 00 } //This might be a string? Looks like:"#$%&'()*+,-./01
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.48345859334435 Found in 10 files
		$x1 = { 6C 00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32 00 4C 64 72 47 65 74 50 72 6F 63 65 64 75 72 } //This might be a string? Looks like:lkernel32LdrGetProcedur
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.3252317300909384 Found in 8 files
		$x3 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 CC CC CC CC CC CC CC CC 0F 0B CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x17 = { 00 B9 00 BA 00 BB 00 BC 00 BD 00 BE 00 BF 00 C0 00 C1 00 C2 00 C3 00 C4 00 C5 00 C6 00 C7 00 C8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 7 files
		$x4 = { 14 93 A8 11 4D 22 D1 09 92 BD D6 8E 0E B6 F9 AC C9 19 B8 BF F3 AF 6C 3F 0F 56 1B 50 A9 4B D9 3A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x18 = { 77 00 78 00 79 00 7A 00 7B 00 7C 00 7D 00 7E 00 7F 00 80 00 81 00 82 00 83 00 84 00 85 00 86 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7264097655573916 Found in 24 files
		$x9 = { 01 00 4C 00 65 00 67 00 61 00 6C 00 54 00 72 00 61 00 64 00 65 00 6D 00 61 00 72 00 6B 00 73 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x11 = { 00 8C 00 8D 00 8E 00 8F 00 90 00 91 00 92 00 93 00 94 00 95 00 96 00 97 00 98 00 99 00 9A 00 9B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.875 Found in 39 files
		$x6 = { 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x13 = { 8A 00 8B 00 8C 00 8D 00 8E 00 8F 00 90 00 91 00 92 00 93 00 94 00 95 00 96 00 97 00 98 00 99 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6875 Found in 10 files
		$x0 = { 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20 00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 } //This might be a string? Looks like:oration. All rig
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x15 = { 60 00 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6A 00 6B 00 6C 00 6D 00 6E 00 6F 00 } //This might be a string? Looks like:`abcdefghijklmno
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.476409765557392 Found in 9 files
		$x2 = { 53 65 72 76 69 63 65 44 69 73 70 6C 61 79 4E 61 6D 65 57 00 00 41 44 56 41 50 49 33 32 2E 64 6C } //This might be a string? Looks like:ServiceDisplayNameWADVAPI32.dl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x16 = { 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5A 00 5B 00 5C 00 5D 00 5E 00 5F 00 } //This might be a string? Looks like:PQRSTUVWXYZ[\]^_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8125 Found in 19 files
		$x8 = { 00 00 00 00 40 00 00 40 2E 72 63 6E 75 6C 67 00 BA 03 00 00 00 30 0A 00 00 10 00 00 00 30 0A 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x19 = { 9C 00 9D 00 9E 00 9F 00 A0 00 A1 00 A2 00 A3 00 A4 00 A5 00 A6 00 A7 00 A8 00 A9 00 AA 00 AB 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 24 files
		$x10 = { C0 A4 C8 A4 D0 A4 D8 A4 E0 A4 E8 A4 F0 A4 F8 A4 00 A5 08 A5 10 A5 18 A5 20 A5 28 A5 30 A5 38 A5 } 

		condition:
(5 of ($x0,$x1,$x2,$x3,$x4) ) or (5 of ($x5,$x6,$x7,$x8,$x9,$x10) ) or (7 of ($x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19) )}