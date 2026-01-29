rule malware_samples_formbook
{
	//Input TP Rate:
	//33/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x1 = { 00 6F 00 6E 00 74 00 72 } //This might be a string? Looks like:ontr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 42 files
		$x2 = "FileVers" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 32 files
		$x83 = { 00 47 65 74 4F 62 6A 65 } //This might be a string? Looks like:GetObje
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 16 files
		$x3 = "oolhelp3" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 16 files
		$x4 = "irectory" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 33 files
		$x84 = { 50 45 00 00 4C 01 03 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x5 = { 56 00 45 00 52 00 54 00 } //This might be a string? Looks like:VERT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x85 = { 6F 75 74 00 52 65 73 75 } //This might be a string? Looks like:outResu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x86 = { 00 73 65 74 5F 4E 61 6D } //This might be a string? Looks like:set_Nam
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x8 = { 05 38 EE 76 1E F9 D2 72 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 21 files
		$x9 = "23456789" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 35 files
		$x10 = { 73 00 69 00 62 00 6C 00 } //This might be a string? Looks like:sibl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 22 files
		$x11 = { 50 72 6F 63 65 73 73 00 } //This might be a string? Looks like:Process
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x12 = { 00 69 00 6F 00 6E 00 20 } //This might be a string? Looks like:ion 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x87 = { 72 53 74 79 6C 65 00 46 } //This might be a string? Looks like:rStyleF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 21 files
		$x14 = "etProces" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 19 files
		$x88 = { 6E 00 67 65 74 5F 4C 69 } //This might be a string? Looks like:nget_Li
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 30 files
		$x89 = { 00 00 0E C3 01 C7 6F A8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 16 files
		$x15 = { 00 6C 00 65 00 67 00 65 } //This might be a string? Looks like:lege
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 27 files
		$x90 = "izeCompo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 20 files
		$x91 = { 0A 00 02 7B 11 00 00 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x17 = { 00 72 00 6D 00 61 00 74 } //This might be a string? Looks like:rmat
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x18 = { 00 74 00 65 00 72 00 20 } //This might be a string? Looks like:ter 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 21 files
		$x92 = { 03 20 00 08 06 20 02 11 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x93 = { 69 6E 00 4D 65 73 73 61 } //This might be a string? Looks like:inMessa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x94 = { 74 00 67 65 74 5F 54 65 } //This might be a string? Looks like:tget_Te
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x95 = { 00 00 0A 00 02 7B 21 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 21 files
		$x96 = { 0A 00 02 7B 19 00 00 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x20 = { 69 00 6E 00 64 00 6F 00 } //This might be a string? Looks like:indo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 26 files
		$x22 = { 65 00 61 00 74 00 65 00 } //This might be a string? Looks like:eate
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x97 = { 3E 00 67 65 74 5F 42 00 } //This might be a string? Looks like:>get_B
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x23 = { 02 03 04 05 06 07 08 09 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x98 = { 78 00 73 65 74 5F 4D 61 } //This might be a string? Looks like:xset_Ma
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 15 files
		$x25 = "haracter" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 49 files
		$x26 = { BD 04 EF FE 00 00 01 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 39 files
		$x27 = { 00 47 65 74 43 75 72 72 } //This might be a string? Looks like:GetCurr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x99 = { 6C 75 65 00 67 65 74 5F } //This might be a string? Looks like:lueget_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 23 files
		$x100 = { 5A 01 00 4B 4D 69 63 72 } //This might be a string? Looks like:ZKMicr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 23 files
		$x101 = { 72 6B 20 34 2E 35 04 01 } //This might be a string? Looks like:rk 4.5
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 20 files
		$x102 = { 00 02 7B 23 00 00 04 72 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 21 files
		$x103 = { 07 2A 00 00 00 13 30 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 46 files
		$x32 = { 69 00 67 00 68 00 74 00 } //This might be a string? Looks like:ight
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 17 files
		$x33 = { 01 00 09 08 00 00 F8 03 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 46 files
		$x34 = "itialize" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x104 = "yConfigu" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x35 = "STUVWXYZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 18 files
		$x36 = { F9 F9 FF F8 F8 F8 FF F7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x38 = { 73 00 75 00 6C 00 74 00 } //This might be a string? Looks like:sult
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 18 files
		$x105 = { 74 65 72 76 61 6C 00 4C } //This might be a string? Looks like:tervalL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 27 files
		$x106 = "t_Client" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x107 = { 6C 74 00 53 65 74 43 6F } //This might be a string? Looks like:ltSetCo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x108 = { 00 00 0A 00 02 7B 1A 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 18 files
		$x42 = { 42 7E DB 9C 43 85 F1 E4 } //This might be a string? Looks like:B~C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 23 files
		$x109 = { 70 65 49 6E 66 6F 00 43 } //This might be a string? Looks like:peInfoC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 47 files
		$x43 = { 04 EF FE 00 00 01 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 28 files
		$x110 = { FE 01 0A 06 2C 22 00 72 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 31 files
		$x48 = { 00 74 00 61 00 74 00 69 } //This might be a string? Looks like:tati
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 27 files
		$x111 = "lignment" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x112 = { 6F 6E 69 6E 67 00 54 6F } //This might be a string? Looks like:oningTo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x113 = { 73 74 65 6D 00 54 72 69 } //This might be a string? Looks like:stemTri
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x50 = { 5F 5E C2 08 00 55 8B EC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 22 files
		$x114 = "howDialo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x115 = { 00 00 0A 7D 08 00 00 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x116 = "Equality" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 47 files
		$x51 = "sembly x" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 48 files
		$x52 = "ublicKey" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x53 = { 65 00 20 00 73 00 75 00 } //This might be a string? Looks like:e su
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x55 = { 00 61 00 62 00 6C 00 65 } //This might be a string? Looks like:able
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 16 files
		$x56 = "ssWindow" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x57 = "Informat" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 18 files
		$x117 = { 00 02 7B 21 00 00 04 20 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 15 files
		$x58 = { A8 25 00 00 09 00 20 20 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 45 files
		$x59 = "xception" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x60 = { 09 08 00 00 B8 04 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 43 files
		$x62 = "ompatibl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x118 = { 00 67 65 74 5F 44 61 72 } //This might be a string? Looks like:get_Dar
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 23 files
		$x119 = { 09 0B 00 00 00 FA 01 33 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x65 = { 00 72 00 20 00 64 00 65 } //This might be a string? Looks like:r de
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x120 = { 00 6D 00 61 00 72 00 6B } //This might be a string? Looks like:mark
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x121 = "pyright " ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x122 = { 74 5F 57 68 69 74 65 00 } //This might be a string? Looks like:t_White
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 29 files
		$x123 = "utral, P" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x124 = { 00 00 0A 7D 19 00 00 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 18 files
		$x72 = "lientRec" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 16 files
		$x73 = { EE FF EC EC EC FF E9 E9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 20 files
		$x74 = { 42 00 75 00 74 00 74 00 } //This might be a string? Looks like:Butt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x125 = { 11 12 1B 5F 1A FE 01 13 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5 Found in 44 files
		$x77 = { 2E 00 30 00 2E 00 30 00 } //This might be a string? Looks like:.0.0
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 27 files
		$x126 = "set_Maxi" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x127 = { 75 72 61 74 69 6F 6E 00 } //This might be a string? Looks like:uration
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x80 = "IsWindow" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x128 = { 30 00 49 45 6E 75 6D 65 } //This might be a string? Looks like:0IEnume
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 31 files
		$x129 = "m.Diagno" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 28 files
		$x130 = { 2E 76 32 22 3E 0D 0A 20 } //This might be a string? Looks like:.v2">\r\n 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x131 = { 00 49 45 4E 44 AE 42 60 } //This might be a string? Looks like:IENDB`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x82 = { 61 00 6C 00 69 00 64 00 } //This might be a string? Looks like:alid
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 21 files
		$x132 = { 00 0A 7D 23 00 00 04 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 37 files
		$x0 = { 00 74 00 65 00 64 00 2E } //This might be a string? Looks like:ted.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4056390622295665 Found in 26 files
		$x133 = { FF 00 00 FF FF 00 00 F8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 28 files
		$x134 = { 6E 00 53 79 73 74 65 6D } //This might be a string? Looks like:nSystem
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 22 files
		$x135 = { 00 5A 01 00 4B 4D 69 63 } //This might be a string? Looks like:ZKMic
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 26 files
		$x136 = { 04 2B 01 16 13 0A 11 0A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x137 = { 6F 00 42 69 74 6D 61 70 } //This might be a string? Looks like:oBitmap
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x138 = { 6D 61 69 6E 00 4D 65 73 } //This might be a string? Looks like:mainMes
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 22 files
		$x139 = { 5F 4E 6F 77 00 53 68 6F } //This might be a string? Looks like:_NowSho
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x140 = { 6E 75 52 FF 65 67 00 FF } //This might be a string? Looks like:nuReg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 29 files
		$x141 = "xml vers" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 21 files
		$x142 = { 00 0A 7D 21 00 00 04 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 28 files
		$x143 = { 75 6C 74 00 44 69 61 6C } //This might be a string? Looks like:ultDial
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x6 = { 00 73 00 74 00 65 00 6D } //This might be a string? Looks like:stem
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4056390622295665 Found in 15 files
		$x7 = { 00 00 00 C0 FF FF FF 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 26 files
		$x144 = { 72 00 61 00 64 00 65 00 } //This might be a string? Looks like:rade
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 41 files
		$x13 = "scriptio" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x16 = { 00 69 00 64 00 65 00 20 } //This might be a string? Looks like:ide 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x145 = { 00 00 0A 7D 11 00 00 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 21 files
		$x146 = { 0A 26 2B 1C 11 04 20 FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 21 files
		$x147 = { 00 41 01 00 33 53 79 73 } //This might be a string? Looks like:A3Sys
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x148 = { 54 69 63 6B 73 00 67 65 } //This might be a string? Looks like:Ticksge
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 26 files
		$x149 = { 65 73 00 4D 69 63 72 6F } //This might be a string? Looks like:esMicro
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x19 = { 6D 62 6C 79 3E 0D 0A 50 } //This might be a string? Looks like:mbly>\r\nP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 26 files
		$x150 = { 65 66 61 75 6C 74 00 53 } //This might be a string? Looks like:efaultS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x21 = { 00 01 00 09 08 00 00 C8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x24 = "oseHandl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 18 files
		$x151 = { 6E 00 67 65 74 5F 47 72 } //This might be a string? Looks like:nget_Gr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 27 files
		$x152 = { 00 1A 2E 4E 45 54 46 72 } //This might be a string? Looks like:.NETFr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 38 files
		$x28 = { 00 20 00 64 00 65 00 74 } //This might be a string? Looks like: det
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x29 = { FB 59 F4 2A F0 77 53 DF } //This might be a string? Looks like:Y*wS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x153 = { 6D 2E 4C 69 6E 71 00 43 } //This might be a string? Looks like:m.LinqC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 21 files
		$x154 = { 74 00 73 65 61 6C 43 6F } //This might be a string? Looks like:tsealCo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 27 files
		$x155 = { 72 00 73 65 74 5F 46 6F } //This might be a string? Looks like:rset_Fo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x156 = "ightBlue" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 20 files
		$x157 = { 00 01 25 16 06 A2 14 14 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.561278124459133 Found in 19 files
		$x30 = { F5 F5 F5 FF F4 F4 F4 FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x31 = { 73 00 65 00 72 00 20 00 } //This might be a string? Looks like:ser 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 27 files
		$x158 = { 08 03 20 00 01 05 20 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 26 files
		$x159 = { 4C 61 62 65 6C 00 53 79 } //This might be a string? Looks like:LabelSy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 23 files
		$x160 = { 42 61 73 65 00 43 6C 6F } //This might be a string? Looks like:BaseClo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x161 = { 61 67 65 00 41 64 64 52 } //This might be a string? Looks like:ageAddR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x37 = "GetValue" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 19 files
		$x162 = { 00 00 0A 0A 06 1C FE 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 18 files
		$x163 = { 67 6E 6D 65 6E 74 00 49 } //This might be a string? Looks like:gnmentI
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 40 files
		$x39 = "etCurren" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 19 files
		$x40 = "QueryVal" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x164 = "MethodBa" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 26 files
		$x165 = { 74 6F 72 00 2E 63 74 6F } //This might be a string? Looks like:tor.cto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 45 files
		$x41 = "ializeCo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 19 files
		$x166 = { 6E 67 00 53 68 6F 77 44 } //This might be a string? Looks like:ngShowD
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 36 files
		$x44 = { 69 00 62 00 6C 00 65 00 } //This might be a string? Looks like:ible
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 17 files
		$x45 = { 65 00 74 00 65 00 20 00 } //This might be a string? Looks like:ete 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x46 = { 68 00 65 00 20 00 63 00 } //This might be a string? Looks like:he c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 21 files
		$x47 = "ileNameW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x167 = { 00 00 0A 00 02 7B 24 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x49 = { 20 00 68 00 61 00 73 00 } //This might be a string? Looks like: has
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 26 files
		$x168 = "roductAt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x169 = { 00 2A 00 00 13 30 04 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 26 files
		$x170 = { 74 74 6F 6E 00 52 75 6E } //This might be a string? Looks like:ttonRun
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x171 = { 61 67 65 42 6F 78 00 73 } //This might be a string? Looks like:ageBoxs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x172 = { 00 1D 13 00 05 00 00 12 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x173 = { 41 72 72 61 79 00 67 65 } //This might be a string? Looks like:Arrayge
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x54 = "vironmen" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 18 files
		$x61 = "arameter" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 50 files
		$x63 = "DOS mode" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x174 = { 72 6C 69 62 00 3C 3E 63 } //This might be a string? Looks like:rlib<>c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 19 files
		$x64 = { 61 00 6C 00 6C 00 65 00 } //This might be a string? Looks like:alle
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 17 files
		$x66 = { F3 F3 FF F2 F2 F2 FF F1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 20 files
		$x67 = "GetStrin" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 25 files
		$x175 = { 67 00 44 65 62 75 67 00 } //This might be a string? Looks like:gDebug
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x176 = { 00 00 0A 00 02 7B 26 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x177 = { 69 6E 67 00 64 69 73 70 } //This might be a string? Looks like:ingdisp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x68 = { 00 6F 00 6E 00 74 00 61 } //This might be a string? Looks like:onta
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x178 = { 00 00 04 14 FE 03 2B 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 16 files
		$x69 = "eOperati" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 46 files
		$x70 = { 0A 3C 2F 61 73 73 65 6D } //This might be a string? Looks like:\n</assem
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x71 = { 00 50 00 61 00 6E 00 65 } //This might be a string? Looks like:Pane
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x179 = { 11 43 6F 70 79 72 69 67 } //This might be a string? Looks like:Copyrig
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 18 files
		$x180 = { 74 69 6F 6E 00 42 75 74 } //This might be a string? Looks like:tionBut
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x75 = { 00 65 00 73 00 74 00 69 } //This might be a string? Looks like:esti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 19 files
		$x76 = { 20 00 69 00 73 00 20 00 } //This might be a string? Looks like: is 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x181 = { 00 00 0A 00 02 7B 23 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x78 = { 00 4D 00 65 00 6E 00 75 } //This might be a string? Looks like:Menu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x79 = "onstruct" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 27 files
		$x182 = { 00 00 42 53 4A 42 01 00 } //This might be a string? Looks like:BSJB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 28 files
		$x183 = { 6F 69 6E 74 00 73 65 74 } //This might be a string? Looks like:ointset
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 32 files
		$x184 = { 4E 00 61 00 6D 00 65 00 } //This might be a string? Looks like:Name
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 26 files
		$x185 = { 0A 02 7B 23 00 00 04 6F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x186 = { 65 00 67 65 74 5F 57 68 } //This might be a string? Looks like:eget_Wh
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 44 files
		$x81 = { 6E 73 74 61 6E 63 65 00 } //This might be a string? Looks like:nstance
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x187 = { 46 00 67 65 74 5F 47 00 } //This might be a string? Looks like:Fget_G

		condition:
(78 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82) ) or (107 of ($x2,$x83,$x84,$x85,$x86,$x10,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x26,$x27,$x99,$x100,$x101,$x102,$x103,$x32,$x34,$x104,$x105,$x106,$x107,$x108,$x109,$x43,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x51,$x52,$x117,$x59,$x62,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x77,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x133,$x0,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x13,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x28,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x39,$x164,$x165,$x41,$x166,$x44,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x63,$x175,$x176,$x177,$x178,$x70,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x81,$x187) )}