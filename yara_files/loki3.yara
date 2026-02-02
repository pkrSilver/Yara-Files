rule malware_samples_loki
{
	//Input TP Rate:
	//25/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 29 files
		$x26 = { 24 E9 0B B1 87 7C 6F 2F 11 4C 68 58 AB 1D 61 C1 3D 2D 66 B6 90 41 DC 76 06 71 DB 01 BC 20 D2 98 } //This might be a string? Looks like:$|o/LhXa=-fAvq 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4358203810934294 Found in 4 files
		$x3 = { 6E 74 69 6D 65 52 65 73 6F 75 72 63 65 53 65 74 02 00 00 00 00 00 00 00 00 00 00 00 50 41 44 50 } //This might be a string? Looks like:ntimeResourceSetPADP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x13 = { 70 33 74 33 78 33 7C 33 80 33 84 33 88 33 8C 33 90 33 94 33 98 33 9C 33 A0 33 A4 33 A8 33 AC 33 } //This might be a string? Looks like:p3t3x3|3333333333333
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.015319531114783 Found in 4 files
		$x5 = { 6F 6E 00 53 79 73 74 65 6D 2E 47 6C 6F 62 61 6C 69 7A 61 74 69 6F 6E 00 53 79 73 74 65 6D 2E 52 } //This might be a string? Looks like:onSystem.GlobalizationSystem.R
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.027518266288633 Found in 5 files
		$x8 = { 70 53 65 72 76 69 63 65 73 00 53 79 73 74 65 6D 2E 52 75 6E 74 69 6D 65 2E 43 6F 6D 70 69 6C 65 } //This might be a string? Looks like:pServicesSystem.Runtime.Compile
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 7 files
		$x17 = { 3B D0 3B D8 3B E0 3B E8 3B F0 3B F8 3B 00 3C 08 3C 10 3C 18 3C 20 3C 28 3C 30 3C 38 3C 40 3C 48 } //This might be a string? Looks like:;;;;;;;<<<< <(<0<8<@<H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.077819531114783 Found in 5 files
		$x10 = { 6E 74 48 61 6E 64 6C 65 72 00 53 79 73 74 65 6D 2E 43 6F 64 65 44 6F 6D 2E 43 6F 6D 70 69 6C 65 } //This might be a string? Looks like:ntHandlerSystem.CodeDom.Compile
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x20 = { 3B 04 3B 08 3B 0C 3B 10 3B 14 3B 18 3B 1C 3B 20 3B 24 3B 28 3B 2C 3B 30 3B 34 3B 38 3B 3C 3B 40 } //This might be a string? Looks like:;;;;;;;; ;$;(;,;0;4;8;<;@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.963710641914682 Found in 4 files
		$x1 = { 01 00 CE CA EF BE 01 00 00 00 91 00 00 00 6C 53 79 73 74 65 6D 2E 52 65 73 6F 75 72 63 65 73 2E } //This might be a string? Looks like:lSystem.Resources.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x31 = { 00 45 00 46 00 47 00 48 00 49 00 4A 00 4B 00 4C 00 4D 00 4E 00 4F 00 50 00 51 00 52 00 53 00 54 } //This might be a string? Looks like:EFGHIJKLMNOPQRST
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.265319531114783 Found in 18 files
		$x24 = { 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 } //This might be a string? Looks like:<trustInfo xmlns="urn:schemas-mi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7889097655573916 Found in 4 files
		$x0 = { 72 65 43 6F 6C 6F 72 00 73 65 74 5F 42 61 63 6B 43 6F 6C 6F 72 00 73 65 74 5F 55 73 65 56 69 73 } //This might be a string? Looks like:reColorset_BackColorset_UseVis
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 6 files
		$x12 = "#$%&'()*+,-./0123456789:;<=>?@ab" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1061450333085068 Found in 9 files
		$x27 = { 00 00 99 54 CD 3C A8 87 10 4B A2 15 60 88 88 DD 3B 55 00 00 00 00 00 00 00 00 00 00 00 00 01 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 9 files
		$x14 = { 33 E4 33 E8 33 EC 33 F0 33 F4 33 F8 33 FC 33 00 34 04 34 08 34 0C 34 10 34 14 34 18 34 1C 34 20 } //This might be a string? Looks like:3333333344444444 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x29 = { 61 00 72 00 65 00 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 57 00 69 00 } //This might be a string? Looks like:are\Microsoft\Wi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 6 files
		$x15 = { 34 E4 34 E8 34 EC 34 F0 34 F4 34 F8 34 FC 34 00 35 04 35 08 35 0C 35 10 35 14 35 18 35 1C 35 20 } //This might be a string? Looks like:4444444455555555 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.537230146650821 Found in 13 files
		$x30 = { 32 C8 AD 89 AC 16 AD 52 69 63 68 88 AC 16 AD 00 00 00 00 00 00 00 00 50 45 00 00 4C 01 04 00 85 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.8042292966721747 Found in 4 files
		$x6 = { 00 41 73 73 65 6D 62 6C 79 46 69 6C 65 56 65 72 73 69 6F 6E 41 74 74 72 69 62 75 74 65 00 41 73 } //This might be a string? Looks like:AssemblyFileVersionAttributeAs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 6 files
		$x16 = { 35 E4 35 E8 35 EC 35 F0 35 F4 35 F8 35 FC 35 00 36 04 36 08 36 0C 36 10 36 14 36 18 36 1C 36 20 } //This might be a string? Looks like:5555555566666666 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7775182662886326 Found in 4 files
		$x7 = { 6C 65 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 54 72 61 64 65 6D 61 72 6B 41 74 74 } //This might be a string? Looks like:leAttributeAssemblyTrademarkAtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 8 files
		$x18 = { CC 3E D0 3E D4 3E D8 3E DC 3E E0 3E E4 3E E8 3E EC 3E F0 3E F4 3E F8 3E FC 3E 00 3F 04 3F 08 3F } //This might be a string? Looks like:>>>>>>>>>>>>>???
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 7 files
		$x19 = { 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F A0 A1 A2 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.4496987351738495 Found in 22 files
		$x33 = { 61 76 2E 72 75 00 00 00 00 00 14 C9 BC BF A8 F8 72 29 C5 F9 5A 41 41 5D CA E8 A8 11 13 C0 A2 DF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.073391110799899 Found in 20 files
		$x34 = { 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 CC CD 78 FE 88 AC 16 AD 88 AC 16 AD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.077819531114783 Found in 4 files
		$x11 = { 00 45 76 65 6E 74 48 61 6E 64 6C 65 72 00 53 79 73 74 65 6D 2E 43 6F 64 65 44 6F 6D 2E 43 6F 6D } //This might be a string? Looks like:EventHandlerSystem.CodeDom.Com
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 23 files
		$x25 = { 6F 2A 37 BE 0B B4 A1 8E 0C C3 1B DF 05 5A 8D EF 02 2D C0 15 F0 D8 78 C2 CE 11 A4 9E 44 45 53 54 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7621987351738495 Found in 4 files
		$x2 = { 69 7A 65 00 73 65 74 5F 43 6C 69 65 6E 74 53 69 7A 65 00 49 53 75 70 70 6F 72 74 49 6E 69 74 69 } //This might be a string? Looks like:izeset_ClientSizeISupportIniti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.577819531114783 Found in 6 files
		$x4 = { 37 66 31 31 64 35 30 61 33 61 05 01 00 00 00 15 53 79 73 74 65 6D 2E 44 72 61 77 69 6E 67 2E 42 } //This might be a string? Looks like:7f11d50a3aSystem.Drawing.B
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.538909765557392 Found in 8 files
		$x21 = { 75 70 70 6F 72 74 65 64 4F 53 20 49 64 3D 22 7B 33 35 31 33 38 62 39 61 2D 35 64 39 36 2D 34 66 } //This might be a string? Looks like:upportedOS Id="{35138b9a-5d96-4f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 30 files
		$x28 = { 67 07 72 13 57 00 05 82 4A BF 95 14 7A B8 E2 AE 2B B1 7B 38 1B B6 0C 9B 8E D2 92 0D BE D5 E5 B7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x22 = { 86 39 8A 39 8E 39 92 39 96 39 9A 39 9E 39 A2 39 A6 39 AA 39 AE 39 B2 39 B6 39 BA 39 BE 39 C2 39 } //This might be a string? Looks like:9999999999999999
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 7 files
		$x23 = { D8 3A E0 3A E8 3A F0 3A F8 3A 00 3B 08 3B 10 3B 18 3B 20 3B 28 3B 30 3B 38 3B 40 3B 48 3B 50 3B } //This might be a string? Looks like::::::;;;; ;(;0;8;@;H;P;
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.093139062229566 Found in 5 files
		$x9 = { 63 6B 43 6F 6C 6F 72 00 73 65 74 5F 55 73 65 56 69 73 75 61 6C 53 74 79 6C 65 42 61 63 6B 43 6F } //This might be a string? Looks like:ckColorset_UseVisualStyleBackCo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.146782221599798 Found in 15 files
		$x32 = { 00 00 00 00 00 00 00 00 00 00 F0 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 } 

		condition:
(7 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11) ) or (12 of ($x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24) ) or (9 of ($x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34) )}