rule redline
{
	//Input TP Rate:
	//31/49
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.538909765557392 Found in 8 files
		$x1 = { 34 2E 30 01 00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C 61 79 4E 61 6D 65 10 2E 4E 45 } //This might be a string? Looks like:4.0TFrameworkDisplayName.NE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9025182662886326 Found in 13 files
		$x2 = { 72 69 62 75 74 65 00 43 6F 6D 70 69 6C 61 74 69 6F 6E 52 65 6C 61 78 61 74 69 6F 6E 73 41 74 74 } //This might be a string? Looks like:ributeCompilationRelaxationsAtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 29 files
		$x11 = { 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9139097655573916 Found in 14 files
		$x7 = { 08 01 00 08 00 00 00 00 00 1E 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78 63 65 70 74 69 6F } //This might be a string? Looks like:TWrapNonExceptio
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 28 files
		$x14 = { D5 EF 89 85 B1 71 1F B5 B6 06 A5 E4 BF 9F 33 D4 B8 E8 A2 C9 07 78 34 F9 00 0F 8E A8 09 96 18 98 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 27 files
		$x8 = { F9 D0 C1 8A C1 24 0F D7 0F BE C0 81 E1 04 04 00 00 8B DA 03 D8 83 C3 10 FF 23 80 7A 0E 05 75 11 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7928377974034158 Found in 8 files
		$x0 = { 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 43 6F 6D 56 69 73 69 62 6C 65 41 74 74 72 } //This might be a string? Looks like:rowsableAttributeComVisibleAttr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.538909765557392 Found in 30 files
		$x9 = { 40 24 C1 E8 1F F7 D0 83 E0 01 C7 45 FC FE FF FF FF 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9375 Found in 28 files
		$x10 = { 65 E8 FF 75 F8 8B 45 FC C7 45 FC FE FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.944548827786958 Found in 12 files
		$x3 = "ersion=4.0.0.0, Culture=neutral," ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 27 files
		$x12 = { 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 } //This might be a string? Looks like:Z[\]^_`abcdefghijklmnopqrstuvwxy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.140319531114783 Found in 10 files
		$x4 = { 67 6C 79 54 79 70 65 64 52 65 73 6F 75 72 63 65 42 75 69 6C 64 65 72 08 31 36 2E 30 2E 30 2E 30 } //This might be a string? Looks like:glyTypedResourceBuilder16.0.0.0
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.390319531114783 Found in 12 files
		$x5 = { 6E 3D 22 31 2E 30 22 3E 0D 0A 20 20 3C 61 73 73 65 6D 62 6C 79 49 64 65 6E 74 69 74 79 20 76 65 } //This might be a string? Looks like:n="1.0">\r\n  <assemblyIdentity ve
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6875 Found in 29 files
		$x13 = { 3B 54 24 14 77 08 72 07 3B 44 24 10 76 01 4E 33 D2 8B C6 4F 75 07 F7 DA F7 D8 83 DA 00 5B 5E 5F } //This might be a string? Looks like:;T$wr;D$vN3Ou[^_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.988608500731241 Found in 10 files
		$x6 = { 52 75 6E 74 69 6D 65 2E 49 6E 74 65 72 6F 70 53 65 72 76 69 63 65 73 00 53 79 73 74 65 6D 2E 52 } //This might be a string? Looks like:Runtime.InteropServicesSystem.R

		condition:
(7 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7) ) or (6 of ($x8,$x9,$x10,$x11,$x12,$x13,$x14) )}