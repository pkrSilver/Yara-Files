rule malware_samples_loki
{
	//Input TP Rate:
	//26/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 6 files
		$x9 = "#$%&'()*+,-./0123456789:;<=>?@ab" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 29 files
		$x1 = { 24 E9 0B B1 87 7C 6F 2F 11 4C 68 58 AB 1D 61 C1 3D 2D 66 B6 90 41 DC 76 06 71 DB 01 BC 20 D2 98 } //This might be a string? Looks like:$|o/LhXa=-fAvq 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x3 = { 61 00 72 00 65 00 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 57 00 69 00 } //This might be a string? Looks like:are\Microsoft\Wi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x10 = { 70 33 74 33 78 33 7C 33 80 33 84 33 88 33 8C 33 90 33 94 33 98 33 9C 33 A0 33 A4 33 A8 33 AC 33 } //This might be a string? Looks like:p3t3x3|3333333333333
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 9 files
		$x11 = { 33 E4 33 E8 33 EC 33 F0 33 F4 33 F8 33 FC 33 00 34 04 34 08 34 0C 34 10 34 14 34 18 34 1C 34 20 } //This might be a string? Looks like:3333333344444444 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 4 files
		$x12 = { 32 D6 32 DA 32 DE 32 E2 32 E6 32 EA 32 EE 32 F2 32 F6 32 FA 32 FE 32 02 33 06 33 0A 33 0E 33 12 } //This might be a string? Looks like:22222222222233\n33
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 5 files
		$x13 = { 39 E4 39 EC 39 F4 39 FC 39 04 3A 0C 3A 14 3A 1C 3A 24 3A 2C 3A 34 3A 3C 3A 44 3A 4C 3A 54 3A 5C } //This might be a string? Looks like:99999::::$:,:4:<:D:L:T:\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 6 files
		$x14 = { 34 E4 34 E8 34 EC 34 F0 34 F4 34 F8 34 FC 34 00 35 04 35 08 35 0C 35 10 35 14 35 18 35 1C 35 20 } //This might be a string? Looks like:4444444455555555 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.537230146650821 Found in 13 files
		$x4 = { 32 C8 AD 89 AC 16 AD 52 69 63 68 88 AC 16 AD 00 00 00 00 00 00 00 00 50 45 00 00 4C 01 04 00 85 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 5 files
		$x15 = { 3C D4 3C D8 3C DC 3C E0 3C E4 3C E8 3C EC 3C F0 3C F4 3C F8 3C FC 3C 00 3D 04 3D 08 3D 0C 3D 10 } //This might be a string? Looks like:<<<<<<<<<<<<====
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 7 files
		$x16 = { 3B D0 3B D8 3B E0 3B E8 3B F0 3B F8 3B 00 3C 08 3C 10 3C 18 3C 20 3C 28 3C 30 3C 38 3C 40 3C 48 } //This might be a string? Looks like:;;;;;;;<<<< <(<0<8<@<H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 8 files
		$x17 = { CC 3E D0 3E D4 3E D8 3E DC 3E E0 3E E4 3E E8 3E EC 3E F0 3E F4 3E F8 3E FC 3E 00 3F 04 3F 08 3F } //This might be a string? Looks like:>>>>>>>>>>>>>???
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.4496987351738495 Found in 22 files
		$x7 = { 61 76 2E 72 75 00 00 00 00 00 14 C9 BC BF A8 F8 72 29 C5 F9 5A 41 41 5D CA E8 A8 11 13 C0 A2 DF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 7 files
		$x18 = { 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F A0 A1 A2 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.073391110799899 Found in 20 files
		$x8 = { 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 CC CD 78 FE 88 AC 16 AD 88 AC 16 AD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 23 files
		$x0 = { 6F 2A 37 BE 0B B4 A1 8E 0C C3 1B DF 05 5A 8D EF 02 2D C0 15 F0 D8 78 C2 CE 11 A4 9E 44 45 53 54 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x19 = { 3B 04 3B 08 3B 0C 3B 10 3B 14 3B 18 3B 1C 3B 20 3B 24 3B 28 3B 2C 3B 30 3B 34 3B 38 3B 3C 3B 40 } //This might be a string? Looks like:;;;;;;;; ;$;(;,;0;4;8;<;@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 30 files
		$x2 = { 67 07 72 13 57 00 05 82 4A BF 95 14 7A B8 E2 AE 2B B1 7B 38 1B B6 0C 9B 8E D2 92 0D BE D5 E5 B7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1686450333085068 Found in 4 files
		$x20 = { 3D 04 3E 0C 3E 14 3E 1C 3E 24 3E 2C 3E 34 3E 3C 3E 44 3E 4C 3E 54 3E 5C 3E 64 3E 6C 3E 74 3E 7C } //This might be a string? Looks like:=>>>>$>,>4><>D>L>T>\>d>l>t>|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x5 = { 00 45 00 46 00 47 00 48 00 49 00 4A 00 4B 00 4C 00 4D 00 4E 00 4F 00 50 00 51 00 52 00 53 00 54 } //This might be a string? Looks like:EFGHIJKLMNOPQRST
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x21 = { 86 39 8A 39 8E 39 92 39 96 39 9A 39 9E 39 A2 39 A6 39 AA 39 AE 39 B2 39 B6 39 BA 39 BE 39 C2 39 } //This might be a string? Looks like:9999999999999999
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x22 = { 3C 9C 3C A0 3C A4 3C A8 3C AC 3C B0 3C B4 3C B8 3C BC 3C C0 3C C4 3C C8 3C CC 3C D0 3C D4 3C D8 } //This might be a string? Looks like:<<<<<<<<<<<<<<<<
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 7 files
		$x23 = { D8 3A E0 3A E8 3A F0 3A F8 3A 00 3B 08 3B 10 3B 18 3B 20 3B 28 3B 30 3B 38 3B 40 3B 48 3B 50 3B } //This might be a string? Looks like::::::;;;; ;(;0;8;@;H;P;
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.146782221599798 Found in 15 files
		$x6 = { 00 00 00 00 00 00 00 00 00 00 F0 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 } 

		condition:
(6 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8) ) or (15 of ($x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23) )}