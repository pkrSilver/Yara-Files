rule malware_samples_redline
{
	//Input TP Rate:
	//29/49
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.738608500731241 Found in 24 files
		$x0 = "PPADDINGXXPADDINGPADDINGXXPADDIN" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9025182662886326 Found in 13 files
		$x22 = { 72 69 62 75 74 65 00 43 6F 6D 70 69 6C 61 74 69 6F 6E 52 65 6C 61 78 61 74 69 6F 6E 73 41 74 74 } //This might be a string? Looks like:ributeCompilationRelaxationsAtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.952819531114783 Found in 25 files
		$x1 = { 00 00 57 6F 77 36 34 52 65 76 65 72 74 57 6F 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6F 6E 00 } //This might be a string? Looks like:Wow64RevertWow64FsRedirection
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.601409765557392 Found in 27 files
		$x4 = { 56 57 8B 48 3C 03 C8 0F B7 41 14 0F B7 59 06 83 C0 18 03 C1 85 DB 74 1B 8B 7D 0C 8B 70 0C 3B FE } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.304229296672174 Found in 30 files
		$x5 = { CC 80 F9 40 73 15 80 F9 20 73 06 0F AD D0 D3 EA C3 8B C2 33 D2 80 E1 1F D3 E8 C3 33 C0 33 D2 C3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.413909765557392 Found in 26 files
		$x6 = { 75 72 63 65 45 78 00 00 EF 01 4C 6F 61 64 49 6D 61 67 65 57 00 00 19 02 4D 6F 6E 69 74 6F 72 46 } //This might be a string? Looks like:urceExLoadImageWMonitorF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.366729296672174 Found in 18 files
		$x8 = { B0 01 5B 8B E5 5D C3 55 8B EC 83 EC 3C 53 56 57 33 F6 B8 80 00 00 00 56 50 6A 03 56 6A 03 8B DA } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 26 files
		$x9 = { A3 A4 A5 0D 0E 5F 0B A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7 E2 01 02 04 05 06 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 27 files
		$x10 = { F9 D0 C1 8A C1 24 0F D7 0F BE C0 81 E1 04 04 00 00 8B DA 03 D8 83 C3 10 FF 23 80 7A 0E 05 75 11 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.538909765557392 Found in 30 files
		$x11 = { 40 24 C1 E8 1F F7 D0 83 E0 01 C7 45 FC FE FF FF FF 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7928377974034158 Found in 8 files
		$x20 = { 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 43 6F 6D 56 69 73 69 62 6C 65 41 74 74 72 } //This might be a string? Looks like:rowsableAttributeComVisibleAttr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.9375 Found in 24 files
		$x12 = { 0D 84 D2 74 D4 5E 33 C0 5B 59 5D C2 04 00 B2 01 EB EF 55 8B EC 83 EC 68 53 56 57 8D 4D 9C E8 CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.4375 Found in 25 files
		$x16 = { C1 24 0F D7 D0 E4 D0 E4 0A C4 0F BE C0 81 E1 04 04 00 00 8B DA 03 D8 83 C3 10 FF 23 E8 C1 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 27 files
		$x17 = { 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 } //This might be a string? Looks like:Z[\]^_`abcdefghijklmnopqrstuvwxy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.140319531114783 Found in 10 files
		$x24 = { 67 6C 79 54 79 70 65 64 52 65 73 6F 75 72 63 65 42 75 69 6C 64 65 72 08 31 36 2E 30 2E 30 2E 30 } //This might be a string? Looks like:glyTypedResourceBuilder16.0.0.0
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.988608500731241 Found in 10 files
		$x26 = { 52 75 6E 74 69 6D 65 2E 49 6E 74 65 72 6F 70 53 65 72 76 69 63 65 73 00 53 79 73 74 65 6D 2E 52 } //This might be a string? Looks like:Runtime.InteropServicesSystem.R
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.726409765557392 Found in 15 files
		$x19 = { 83 C0 02 0F B7 08 66 85 C9 75 DC 33 C0 5F 5E 5B 5D C3 6A 14 68 B8 A0 4B 00 E8 9E 0C 00 00 E8 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.538909765557392 Found in 8 files
		$x21 = { 34 2E 30 01 00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C 61 79 4E 61 6D 65 10 2E 4E 45 } //This might be a string? Looks like:4.0TFrameworkDisplayName.NE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 16 files
		$x2 = { 8B F9 85 F6 74 15 8D 46 FF 50 52 57 E8 54 FB 01 00 83 C4 0C 33 C0 66 89 44 77 FE 5F 5E 5D C3 55 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 29 files
		$x3 = { 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9139097655573916 Found in 14 files
		$x27 = { 08 01 00 08 00 00 00 00 00 1E 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78 63 65 70 74 69 6F } //This might be a string? Looks like:TWrapNonExceptio
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 28 files
		$x7 = { D5 EF 89 85 B1 71 1F B5 B6 06 A5 E4 BF 9F 33 D4 B8 E8 A2 C9 07 78 34 F9 00 0F 8E A8 09 96 18 98 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9375 Found in 28 files
		$x13 = { 65 E8 FF 75 F8 8B 45 FC C7 45 FC FE FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.077819531114783 Found in 18 files
		$x14 = { 67 79 70 74 69 61 6E 5F 48 69 65 72 6F 67 6C 79 70 68 73 00 45 74 68 69 6F 70 69 63 00 47 65 6F } //This might be a string? Looks like:gyptian_HieroglyphsEthiopicGeo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.323391110799899 Found in 20 files
		$x15 = { 00 00 0D 88 84 81 FF F7 F5 F3 FF FB F9 F6 FF D1 BD BC FF 8C 95 50 FF 8B 97 51 FF 89 9A 53 FF 87 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.944548827786958 Found in 12 files
		$x23 = "ersion=4.0.0.0, Culture=neutral," ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6875 Found in 29 files
		$x18 = { 3B 54 24 14 77 08 72 07 3B 44 24 10 76 01 4E 33 D2 8B C6 4F 75 07 F7 DA F7 D8 83 DA 00 5B 5E 5F } //This might be a string? Looks like:;T$wr;D$vN3Ou[^_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.390319531114783 Found in 12 files
		$x25 = { 6E 3D 22 31 2E 30 22 3E 0D 0A 20 20 3C 61 73 73 65 6D 62 6C 79 49 64 65 6E 74 69 74 79 20 76 65 } //This might be a string? Looks like:n="1.0">\r\n  <assemblyIdentity ve

		condition:
(15 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19) ) or (7 of ($x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27) )}