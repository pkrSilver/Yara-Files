rule vidar3
{
	//Input TP Rate:
	//33/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 39 files
		$x0 = "formanceFrequenc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 13 files
		$x377 = { F0 3F 00 E4 0B 54 02 00 00 00 00 00 10 63 2D 5E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 21 files
		$x57 = { A6 08 A6 10 A6 18 A6 20 A6 28 A6 30 A6 38 A6 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 30 files
		$x58 = "?AVexception@std" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 16 files
		$x59 = { CC CC 55 41 57 41 56 41 54 56 57 53 48 83 EC 10 } //This might be a string? Looks like:UAWAVATVWSH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 19 files
		$x61 = { 5F C3 CC CC CC CC CC CC CC CC 41 57 41 56 41 55 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1556390622295662 Found in 18 files
		$x63 = { 48 8B 44 24 28 48 8B 00 48 8B 4C 24 28 FF 50 08 } //This might be a string? Looks like:HD$(HHL$(P
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 18 files
		$x64 = { 41 54 56 57 53 48 83 EC 58 48 8D 6C 24 50 48 8B } //This might be a string? Looks like:ATVWSHXHl$PH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8993974703476995 Found in 19 files
		$x382 = { 5E 41 5F C3 CC CC 41 57 41 56 41 55 41 54 56 57 } //This might be a string? Looks like:^A_AWAVAUATVW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 25 files
		$x66 = { A9 F0 A9 F8 A9 00 AA 08 AA 10 AA 18 AA 20 AA 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 48 files
		$x7 = { B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 20 70 72 } //This might be a string? Looks like:\t!L!This pr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 9 files
		$x67 = { 8F 84 13 00 00 31 C1 89 C8 C1 E0 07 25 80 56 2C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7806390622295662 Found in 16 files
		$x385 = { 7E E6 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 44 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 25 files
		$x70 = { C8 AB D0 AB D8 AB E0 AB E8 AB F0 AB F8 AB 00 AC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 16 files
		$x386 = { FF FF 48 8B 9C 24 88 00 00 00 48 83 C4 50 41 5F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 11 files
		$x387 = { BC D0 4D 85 D2 75 06 41 8D 79 F2 EB 11 B9 10 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 15 files
		$x72 = { 00 48 89 F0 48 83 C4 40 5E C3 CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x73 = { 0A 00 00 5B 5D 5F 5E 41 5C 41 5D 41 5E 41 5F C3 } //This might be a string? Looks like:\n[]_^A\A]A^A_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 14 files
		$x390 = { CC CC CC CC CC CC CC CC 40 55 48 83 EC 20 48 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5306390622295662 Found in 11 files
		$x76 = { CC CC CC CC CC CC 56 57 48 83 EC 48 48 89 CF 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 26 files
		$x78 = { B8 A1 C8 A1 D8 A1 E8 A1 F8 A1 08 A2 18 A2 28 A2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8993974703476995 Found in 22 files
		$x80 = { FE FF FF 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 14 files
		$x392 = { 0B 00 00 85 C0 75 04 8B C3 EB 14 83 F8 01 0F B6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 14 files
		$x394 = { 89 F8 48 83 C4 48 5B 5D 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like:HH[]_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7743974703476995 Found in 20 files
		$x83 = { 5E 41 5F C3 CC CC CC CC 41 57 41 56 41 55 41 54 } //This might be a string? Looks like:^A_AWAVAUAT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 9 files
		$x395 = { 5E 41 5C 41 5E 41 5F 5D C3 66 2E 0F 1F 84 00 00 } //This might be a string? Looks like:^A\A^A_]f.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 19 files
		$x84 = { 60 08 C0 06 D0 04 E0 02 F0 00 00 01 13 0A 00 13 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7743974703476995 Found in 12 files
		$x85 = { CC CC CC CC CC 56 57 48 83 EC 48 48 89 CF 48 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 15 files
		$x88 = { 57 53 48 81 EC B8 00 00 00 48 8D AC 24 80 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.60845859334435 Found in 10 files
		$x397 = { 74 0F 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 00 EB } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.305036532577266 Found in 18 files
		$x398 = { 41 5E 41 5F C3 CC CC CC CC CC CC 41 57 41 56 41 } //This might be a string? Looks like:A^A_AWAVA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 19 files
		$x399 = { F8 A6 08 A7 18 A7 28 A7 38 A7 48 A7 58 A7 68 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 21 files
		$x91 = { 14 32 10 70 01 06 02 00 06 B2 02 30 11 0A 04 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 9 files
		$x401 = { FD FF 90 48 83 C4 28 5B 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like:H([_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 16 files
		$x402 = { 5F 5D C3 CC CC CC CC CC CC CC CC 41 57 41 56 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 29 files
		$x95 = { A9 E0 A9 E8 A9 F0 A9 F8 A9 00 AA 08 AA 10 AA 18 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 10 files
		$x96 = { 8D 78 FF 0F AF F8 40 F6 C7 01 0F 94 C0 0F 94 44 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 12 files
		$x97 = { 5E C3 CC 41 57 41 56 41 55 41 54 56 57 55 53 48 } //This might be a string? Looks like:^AWAVAUATVWUSH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 11 files
		$x98 = { D0 F6 C2 01 0F 94 44 24 22 83 F9 0A 0F 9C 44 24 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 11 files
		$x99 = { 0D 0A 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C } //This might be a string? Looks like:\r\n<trustInfo xml
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 20 files
		$x100 = { 0E 08 00 0E 72 0A 30 09 50 08 70 07 60 06 C0 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 18 files
		$x101 = { 08 83 C1 01 81 E1 00 FF FF FF F7 D9 8D 04 08 83 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 16 files
		$x102 = { 00 4C 89 F0 48 83 C4 38 5B 5F 5E 41 5E C3 CC CC } //This might be a string? Looks like:LH8[_^A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 15 files
		$x406 = { 90 48 83 C4 28 C3 CC CC CC 48 89 5C 24 08 48 89 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 18 files
		$x103 = { 5E C3 41 57 41 56 41 55 41 54 56 57 55 53 48 83 } //This might be a string? Looks like:^AWAVAUATVWUSH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 12 files
		$x408 = { 74 0A 05 DF FA 6C E6 83 F8 01 77 40 48 8B 41 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.091917186688699 Found in 19 files
		$x106 = { 5C 41 5E 41 5F 5D C3 CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1556390622295662 Found in 13 files
		$x107 = { FF FF FF 48 8B 74 24 28 48 8B 4C 24 30 48 31 E1 } //This might be a string? Looks like:Ht$(HL$0H1
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 24 files
		$x108 = { 57 DB 48 89 7C 24 28 0F 28 D6 8B D6 F2 0F 11 44 } //This might be a string? Looks like:WH|$((D
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 16 files
		$x409 = { FF FF FF 66 2E 0F 1F 84 00 00 00 00 00 90 81 F9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.827819531114783 Found in 12 files
		$x109 = { 24 40 48 89 4C 24 20 48 8B 44 24 20 48 89 44 24 } //This might be a string? Looks like:$@HL$ HD$ HD$
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 18 files
		$x35 = "WaitForMultipleO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 18 files
		$x36 = { 00 00 80 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 29 files
		$x112 = "temTimePreciseAs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 27 files
		$x113 = { F8 A2 00 A3 08 A3 10 A3 18 A3 20 A3 28 A3 30 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 14 files
		$x114 = { 01 17 00 0C 30 0B 70 0A 60 09 C0 07 D0 05 E0 03 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 19 files
		$x117 = { 41 5F 5D C3 CC CC CC CC CC CC CC CC 41 57 41 56 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 25 files
		$x119 = { A8 A6 B8 A6 C8 A6 D8 A6 E8 A6 F8 A6 08 A7 18 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 22 files
		$x414 = { A0 E0 A0 E8 A0 F0 A0 F8 A0 00 A1 08 A1 10 A1 18 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 11 files
		$x123 = { 0A 60 09 C0 07 D0 05 E0 03 F0 01 50 00 00 01 13 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 26 files
		$x125 = { 89 44 24 48 48 89 4C 24 50 48 89 54 24 58 48 8B } //This might be a string? Looks like:D$HHL$PHT$XH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 22 files
		$x44 = { 20 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 } //This might be a string? Looks like: DOS mode.\r\r\n$
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 20 files
		$x126 = { 57 41 56 41 55 41 54 56 57 53 48 83 EC 58 48 8D } //This might be a string? Looks like:WAVAUATVWSHXH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 43 files
		$x48 = "tiByteToWideChar" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.25 Found in 14 files
		$x128 = { 50 0F 11 74 24 40 48 C7 44 24 58 00 00 00 00 C7 } //This might be a string? Looks like:Pt$@HD$X
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 20 files
		$x54 = "GetFullPathNameW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.3244602933016414 Found in 13 files
		$x420 = { CC CC E9 0B 00 00 00 CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 25 files
		$x1 = { 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F } //This might be a string? Looks like:ctVersio
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 35 files
		$x135 = "klmnopqrstuvwxyz" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8584585933443494 Found in 15 files
		$x136 = { 44 24 38 48 8B 44 24 38 48 8B 00 48 89 44 24 40 } //This might be a string? Looks like:D$8HD$8HHD$@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 18 files
		$x4 = "FileAttributesEx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x138 = { 8D 50 FF 0F AF D0 F6 C2 01 0F 94 45 BE 83 F9 0A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 9 files
		$x424 = { 0F 30 0E 70 0D 60 0C C0 0A E0 08 F0 06 50 01 17 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 23 files
		$x139 = { 10 22 0C 30 0B 70 0A 60 09 C0 07 D0 05 E0 03 F0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 34 files
		$x141 = { 43 72 69 74 69 63 61 6C 53 65 63 74 69 6F 6E 00 } //This might be a string? Looks like:CriticalSection
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 22 files
		$x142 = { CC CC CC CC 40 55 48 83 EC 20 48 8B EA 48 8B 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 25 files
		$x144 = "leepConditionVar" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6493974703476995 Found in 18 files
		$x145 = { 5E 41 5F C3 CC CC CC CC CC 55 41 57 41 56 41 55 } //This might be a string? Looks like:^A_UAWAVAU
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 32 files
		$x146 = "3456789:;<=>?@AB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 19 files
		$x147 = { AC 08 AC 10 AC 18 AC 20 AC 28 AC 30 AC 38 AC 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 10 files
		$x427 = { F2 01 41 89 C0 41 30 D0 08 C2 80 F2 01 44 08 C2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 45 files
		$x8 = { 65 72 6D 69 6E 61 74 65 50 72 6F 63 65 73 73 00 } //This might be a string? Looks like:erminateProcess
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 20 files
		$x429 = { A1 10 A1 18 A1 20 A1 28 A1 30 A1 38 A1 40 A1 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 28 files
		$x152 = { 00 55 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74 69 } //This might be a string? Looks like:Unknown excepti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 37 files
		$x154 = { AB F0 AB 00 AC 10 AC 20 AC 30 AC 40 AC 50 AC 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 9 files
		$x430 = { 48 8B DA 48 8B F9 E8 03 FF FF FF B2 20 48 89 5F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 31 files
		$x157 = { A4 40 A4 48 A4 50 A4 58 A4 60 A4 68 A4 70 A4 78 } //This might be a string? Looks like:@HPX`hpx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 13 files
		$x431 = { 61 64 62 69 74 20 73 65 74 00 25 70 00 55 6E 6B } //This might be a string? Looks like:adbit set%pUnk
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1084585933443494 Found in 21 files
		$x16 = "etCurrentDirecto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 18 files
		$x158 = { 5D 41 5E 41 5F C3 CC CC CC CC CC CC CC CC 55 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 19 files
		$x159 = { CC 41 57 41 56 41 54 56 57 55 53 48 83 EC 40 48 } //This might be a string? Looks like:AWAVATVWUSH@H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 27 files
		$x160 = { 72 61 74 6F 72 27 00 00 60 76 65 63 74 6F 72 20 } //This might be a string? Looks like:rator'`vector 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 28 files
		$x162 = "olicyGetProcessT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 21 files
		$x165 = { 01 15 0B 00 15 68 03 00 10 82 0C 30 0B 50 0A 70 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.25 Found in 46 files
		$x19 = "FlushFileBuffers" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 21 files
		$x168 = { 00 48 83 C4 20 4C 89 E8 48 8D 65 08 5B 5F 5E 41 } //This might be a string? Looks like:H LHe[_^A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 13 files
		$x169 = { 55 41 54 56 57 55 53 48 83 EC 48 48 89 CE 48 8B } //This might be a string? Looks like:UATVWUSHHHH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 9 files
		$x437 = { 03 D0 48 8D 4D 10 E8 3F 60 01 00 85 C0 74 04 33 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 20 files
		$x23 = { 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 } //This might be a string? Looks like:tThreadContext
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 34 files
		$x26 = { 49 6E 66 6F 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A } //This might be a string? Looks like:Info xmlns="urn:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 19 files
		$x27 = { 3F 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D } //This might be a string? Looks like:?>\r\n<assembly xm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 25 files
		$x177 = { 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E } //This might be a string? Looks like:?xml version="1.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.3993974703476995 Found in 27 files
		$x179 = { 00 00 08 00 00 02 08 02 07 03 08 05 00 05 07 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 15 files
		$x180 = { 38 48 83 C4 20 5F C3 48 89 5C 24 08 57 48 83 EC } //This might be a string? Looks like:8H _H\$WH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 19 files
		$x181 = { 48 29 C4 48 89 E0 48 89 45 B0 B8 10 00 00 00 E8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 16 files
		$x439 = { 0A 0B 0C 0D 0E 0F 00 01 02 03 04 05 06 07 08 09 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 20 files
		$x39 = "eZoneInformation" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.474601752714581 Found in 21 files
		$x186 = { AF A8 AF B8 AF C8 AF D8 AF E8 AF F8 AF 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 28 files
		$x187 = { 00 00 00 60 64 65 66 61 75 6C 74 20 63 6F 6E 73 } //This might be a string? Looks like:`default cons
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 9 files
		$x441 = { 34 01 20 C2 08 DA 89 C3 20 CB 30 C8 08 D8 89 C1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 10 files
		$x192 = { 48 8D 65 08 5B 5F 5E 41 5E 41 5F 5D C3 CC CC CC } //This might be a string? Looks like:He[_^A^A_]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 17 files
		$x42 = { 53 77 69 74 63 68 54 6F 54 68 72 65 61 64 00 00 } //This might be a string? Looks like:SwitchToThread
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 27 files
		$x194 = { B8 A0 C8 A0 D8 A0 E8 A0 F8 A0 08 A1 18 A1 28 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x195 = { 00 2D 00 00 00 00 00 00 00 64 64 64 64 2C 20 4D } //This might be a string? Looks like:-dddd, M
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 14 files
		$x196 = { C1 F7 D9 0F 4C C8 69 C1 97 75 00 00 C1 E8 05 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.25 Found in 28 files
		$x197 = "nitializeSListHe" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 32 files
		$x198 = { 48 A4 50 A4 58 A4 60 A4 68 A4 70 A4 78 A4 80 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 38 files
		$x200 = { B0 AA C0 AA D0 AA E0 AA F0 AA 00 AB 10 AB 20 AB } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x201 = { 06 00 8D 50 FF 0F AF D0 F6 C2 01 0F 94 44 24 2E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 13 files
		$x207 = { 00 00 00 00 00 00 00 00 3C 3F 78 6D 6C 20 76 65 } //This might be a string? Looks like:<?xml ve
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 48 files
		$x52 = "tCurrentProcessI" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 26 files
		$x209 = { AE D8 AE E8 AE F8 AE 08 AF 18 AF 28 AF 38 AF 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 21 files
		$x446 = { 10 A1 18 A1 20 A1 28 A1 30 A1 38 A1 40 A1 48 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 31 files
		$x210 = { A5 40 A5 48 A5 50 A5 58 A5 60 A5 68 A5 70 A5 78 } //This might be a string? Looks like:@HPX`hpx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 15 files
		$x214 = { 0B 50 0A 70 09 60 08 C0 06 D0 04 E0 02 F0 01 10 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 32 files
		$x215 = { 47 65 74 50 72 6F 63 65 73 73 48 65 61 70 00 00 } //This might be a string? Looks like:GetProcessHeap
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 17 files
		$x216 = { 41 5C 41 5D 41 5E 41 5F C3 CC 55 41 57 41 56 41 } //This might be a string? Looks like:A\A]A^A_UAWAVA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 20 files
		$x220 = { 72 61 79 20 6E 65 77 20 6C 65 6E 67 74 68 00 73 } //This might be a string? Looks like:ray new lengths
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 12 files
		$x221 = { 57 41 56 56 57 53 48 83 EC 18 48 8D 6C 24 10 48 } //This might be a string? Looks like:WAVVWSHHl$H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 19 files
		$x222 = { 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 48 41 } //This might be a string? Looks like:WAVAUATVWUSHHA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 9 files
		$x451 = { 0F 95 C1 41 83 F8 09 0F 9F C0 41 83 F8 0A 0F 9C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8993974703476995 Found in 19 files
		$x452 = { 5E 41 5F C3 CC CC 55 41 57 41 56 41 55 41 54 56 } //This might be a string? Looks like:^A_UAWAVAUATV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 17 files
		$x6 = "tTokenInformatio" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 9 files
		$x224 = { C4 20 5F C3 E8 A2 D3 FE FF 85 C0 74 DF 48 8B CB } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 14 files
		$x225 = { 83 EC 50 F2 0F 10 84 24 80 00 00 00 8B D9 F2 0F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x454 = { FF FF 49 03 C4 EB 02 33 C0 80 78 10 00 75 5D 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.311278124459133 Found in 26 files
		$x455 = { C3 CC CC CC CC CC CC CC CC CC CC CC CC 48 83 EC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 16 files
		$x9 = { 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 } //This might be a string? Looks like:GetProcAddress
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 22 files
		$x232 = { 41 54 56 57 53 48 83 EC 18 48 8D 6C 24 10 48 8B } //This might be a string? Looks like:ATVWSHHl$H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 19 files
		$x456 = { 03 00 48 33 C4 48 89 85 50 01 00 00 48 8B BD D0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.091917186688699 Found in 18 files
		$x233 = { 5D 41 5E 41 5F C3 CC CC CC CC CC CC CC CC CC 55 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 38 files
		$x237 = { A2 60 A2 70 A2 80 A2 90 A2 A0 A2 B0 A2 C0 A2 D0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6493974703476995 Found in 20 files
		$x238 = { 5E 41 5C 41 5D 41 5E 41 5F C3 CC CC CC CC CC 55 } //This might be a string? Looks like:^A\A]A^A_U
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 22 files
		$x239 = { CC CC B8 01 00 00 00 C3 CC CC 40 53 48 83 EC 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.224601752714581 Found in 11 files
		$x240 = { 2E 0F 1F 84 00 00 00 00 00 0F 1F 44 00 00 0F 44 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 13 files
		$x242 = { 41 54 56 57 55 53 48 83 EC 58 48 89 CE 48 8B 05 } //This might be a string? Looks like:ATVWUSHXHH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6216407621868583 Found in 16 files
		$x243 = { CC CC CC CC CC CC CC CC CC CC CC 56 48 83 EC 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 15 files
		$x244 = { 00 48 89 F0 0F 28 74 24 30 48 83 C4 48 5B 5D 5F } //This might be a string? Looks like:H(t$0HH[]_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 14 files
		$x245 = { 00 48 89 F0 48 83 C4 38 5F 5E C3 CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 36 files
		$x15 = { 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 } //This might be a string? Looks like:="urn:schemas-mi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 14 files
		$x248 = { 5C 24 10 48 89 74 24 18 55 57 41 54 41 56 41 57 } //This might be a string? Looks like:\$Ht$UWATAVAW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 21 files
		$x249 = { AD 58 AD 68 AD 78 AD 88 AD 98 AD A8 AD B8 AD C8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x22 = { 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 } //This might be a string? Looks like:CompanyN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 9 files
		$x461 = { F2 01 89 D3 20 C3 34 01 20 C1 08 D9 89 C3 20 D3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x462 = { 40 A3 48 A3 50 A3 58 A3 60 A3 68 A3 70 A3 78 A3 } //This might be a string? Looks like:@HPX`hpx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 25 files
		$x25 = "WaitForSingleObj" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 19 files
		$x256 = { AC E0 AC E8 AC F0 AC F8 AC 00 AD 08 AD 10 AD 18 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 13 files
		$x259 = { 8B 43 20 41 83 F8 FF 74 08 45 03 CD 44 3B CE 7C } //This might be a string? Looks like:C AtED;|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.474601752714581 Found in 16 files
		$x463 = { 00 00 00 20 64 65 6C 65 74 65 5B 5D 00 00 00 00 } //This might be a string? Looks like: delete[]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 19 files
		$x30 = { 01 82 37 02 01 0B 31 0E 30 0C 06 0A 2B 06 01 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 24 files
		$x31 = { 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 } //This might be a string? Looks like:galCopyr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 9 files
		$x260 = { 8D 50 FF 0F AF D0 F6 C2 01 0F 94 45 FC 83 F9 0A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 9 files
		$x261 = { 01 00 48 8B E8 48 8D 48 01 48 83 F9 01 76 2D 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8584585933443494 Found in 12 files
		$x263 = { 4C 24 20 48 8B 44 24 20 48 89 44 24 28 48 8B 44 } //This might be a string? Looks like:L$ HD$ HD$(HD
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.311278124459133 Found in 15 files
		$x464 = { 5D C3 CC CC CC CC CC CC CC CC CC CC CC CC 55 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 10 files
		$x267 = { 03 00 00 48 8D 0C 89 44 8B 8C C8 18 01 00 00 44 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1084585933443494 Found in 20 files
		$x37 = { 07 F3 0F 7F 4F 10 F3 0F 7F 57 20 F3 0F 7F 5F 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6266144718101818 Found in 13 files
		$x466 = { CC CC CC CC CC CC CC CC CC CC 48 83 EC 48 48 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 20 files
		$x271 = { F9 1F C1 E9 18 8D 0C 08 83 C1 01 81 E1 00 FF FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.271782221599798 Found in 15 files
		$x272 = { 5E C3 CC CC CC CC CC CC CC 41 57 41 56 41 55 41 } //This might be a string? Looks like:^AWAVAUA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.216917186688699 Found in 21 files
		$x273 = { CC CC CC CC CC CC CC CC CC 56 57 55 53 48 83 EC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 18 files
		$x274 = { 01 0C 07 00 0C 82 08 30 07 50 06 70 05 60 04 E0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 15 files
		$x469 = { 56 41 55 41 54 56 57 55 53 48 83 EC 78 48 8B 05 } //This might be a string? Looks like:VAUATVWUSHxH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 20 files
		$x276 = { AB 50 AB 58 AB 60 AB 68 AB 70 AB 78 AB 80 AB 88 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 19 files
		$x471 = { FD FF CC CC CC CC CC CC 40 55 48 83 EC 20 48 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 11 files
		$x279 = { E1 0F 81 E1 00 00 C6 EF 31 C1 89 CE C1 EE 12 31 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 25 files
		$x280 = { A5 F8 A5 00 A6 08 A6 10 A6 18 A6 20 A6 28 A6 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 21 files
		$x283 = { 6C 73 65 00 62 61 64 20 6C 6F 63 61 6C 65 20 6E } //This might be a string? Looks like:lsebad locale n
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 17 files
		$x473 = { 04 00 10 A2 0C 30 0B 50 0A 70 09 60 08 C0 06 D0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 27 files
		$x285 = { 74 12 81 3F 4D 4F 43 E0 74 0A 81 3F 63 73 6D E0 } //This might be a string? Looks like:t?MOCt\n?csm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 16 files
		$x51 = { 00 47 65 74 43 6F 6E 73 6F 6C 65 4D 6F 64 65 00 } //This might be a string? Looks like:GetConsoleMode
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 16 files
		$x474 = { 73 65 3A 3A 62 61 64 62 69 74 20 73 65 74 00 25 } //This might be a string? Looks like:se::badbit set%
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.85845859334435 Found in 14 files
		$x475 = { 11 44 24 70 0F 11 84 24 80 00 00 00 0F 11 84 24 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 15 files
		$x289 = { 40 5B 5D 5F 5E 41 5E C3 CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 17 files
		$x291 = { 48 83 C4 40 5B 5D 5F 5E 41 5E C3 CC CC CC CC CC } //This might be a string? Looks like:H@[]_^A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.091917186688699 Found in 13 files
		$x292 = { 38 5B 5F 5E 41 5E C3 CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 10 files
		$x295 = { FF 0F AF F8 40 F6 C7 01 0F 94 45 E6 83 FB 0A 0F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 20 files
		$x297 = { 82 FF FF 48 8B 5C 24 30 48 83 C4 20 5F C3 CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 16 files
		$x299 = { 00 11 01 16 00 0A 30 09 50 08 70 07 60 06 C0 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 12 files
		$x478 = { 0F 11 54 24 18 53 48 83 EC 50 45 33 C9 4C 8D 15 } //This might be a string? Looks like:T$SHPE3L
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6556390622295662 Found in 18 files
		$x305 = { 41 5E 41 5F C3 55 41 57 41 56 41 55 41 54 56 57 } //This might be a string? Looks like:A^A_UAWAVAUATVW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.646782221599798 Found in 18 files
		$x306 = { CC CC CC CC CC CC CC 41 56 56 57 53 48 83 EC 38 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.125 Found in 13 files
		$x479 = { C7 44 24 28 00 00 00 00 C7 44 24 20 00 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 9 files
		$x480 = { 49 73 56 61 6C 69 64 4C 6F 63 61 6C 65 00 E2 03 } //This might be a string? Looks like:IsValidLocale
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 17 files
		$x311 = { 48 31 E0 48 89 44 24 40 48 89 4C 24 20 48 8B 44 } //This might be a string? Looks like:H1HD$@HL$ HD
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 17 files
		$x481 = { 00 89 D8 48 83 C4 38 5B 5D 5F 5E 41 5C 41 5D 41 } //This might be a string? Looks like:H8[]_^A\A]A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 27 files
		$x13 = { 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 } //This might be a string? Looks like:tVersion
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6216407621868583 Found in 17 files
		$x313 = { 83 C4 40 5E C3 CC CC CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0243974703476995 Found in 13 files
		$x315 = "osoft Corporatio" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 17 files
		$x14 = { 0A 20 20 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D } //This might be a string? Looks like:\n  <trustInfo xm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 18 files
		$x316 = { 74 24 70 48 83 C4 50 5F C3 CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 45 files
		$x17 = "eEnvironmentStri" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x318 = { A6 50 A6 58 A6 60 A6 68 A6 70 A6 78 A6 80 A6 88 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 13 files
		$x482 = { 02 00 8B D8 EB 17 83 FB FC 75 12 48 8B 44 24 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 26 files
		$x321 = { 00 00 00 00 00 40 00 00 C0 2E 70 64 61 74 61 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 21 files
		$x322 = { AC 98 AC A8 AC B8 AC C8 AC D8 AC E8 AC F8 AC 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 22 files
		$x324 = { 83 C4 30 5B 5D 5F 5E 41 5E C3 CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 21 files
		$x325 = { 85 C0 75 09 8B 44 24 30 48 83 C4 28 C3 48 8D 0D } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 15 files
		$x327 = { 6C 6F 63 6B 00 00 00 61 72 67 75 6D 65 6E 74 20 } //This might be a string? Looks like:lockargument 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 15 files
		$x328 = { CC CC CC CC CC CC CC CC 56 57 53 48 83 EC 30 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 12 files
		$x330 = { 8B 00 48 89 44 24 40 48 8B 44 24 30 48 8B 40 18 } //This might be a string? Looks like:HD$@HD$0H@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.311278124459133 Found in 12 files
		$x484 = { 5F C3 CC CC CC CC CC CC CC CC CC CC CC CC 48 83 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1556390622295662 Found in 17 files
		$x331 = { 00 00 00 47 65 74 53 79 73 74 65 6D 54 69 6D 65 } //This might be a string? Looks like:GetSystemTime
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.936278124459133 Found in 15 files
		$x487 = { 00 00 00 00 F0 7F FF FF FF FF FF FF EF 7F 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 18 files
		$x337 = "processorArchite" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x489 = { CC CC CC CC 41 57 41 56 56 57 55 53 48 83 EC 48 } //This might be a string? Looks like:AWAVVWUSHH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 44 files
		$x32 = { 45 78 63 65 70 74 69 6F 6E 46 69 6C 74 65 72 00 } //This might be a string? Looks like:ExceptionFilter
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 13 files
		$x339 = { 41 56 41 55 41 54 56 57 55 53 48 83 EC 38 4C 89 } //This might be a string? Looks like:AVAUATVWUSH8L
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 21 files
		$x340 = { FF 48 8B 75 F0 48 8B 4D 00 48 31 E9 48 83 EC 20 } //This might be a string? Looks like:HuHMH1H 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 21 files
		$x341 = { CC CC CC CC CC CC CC CC CC CC 41 56 56 57 55 53 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 16 files
		$x491 = { 18 A7 28 A7 38 A7 48 A7 58 A7 68 A7 78 A7 88 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6556390622295662 Found in 9 files
		$x492 = { 28 5B 5F 5E 41 5E 41 5F 5D C3 CC CC CC CC CC CC } //This might be a string? Looks like:([_^A^A_]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7743974703476995 Found in 12 files
		$x344 = { FF E9 6F FF FF FF 66 2E 0F 1F 84 00 00 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 27 files
		$x345 = { 00 69 6E 76 61 6C 69 64 20 61 72 67 75 6D 65 6E } //This might be a string? Looks like:invalid argumen
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 10 files
		$x346 = { 20 48 8B CF 48 89 5F 48 E8 44 FF FF FF 48 83 7F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 11 files
		$x348 = { 20 80 7D F8 00 74 0F 8B 5D F4 48 8D 4D C0 E8 85 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 20 files
		$x354 = { 48 29 C4 48 89 E0 48 89 45 D8 B8 10 00 00 00 E8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x356 = { AD 88 AD 98 AD A8 AD B8 AD C8 AD D8 AD E8 AD F8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 38 files
		$x357 = { A3 F0 A3 00 A4 10 A4 20 A4 30 A4 40 A4 50 A4 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 11 files
		$x358 = { 00 00 00 89 C1 F7 D9 0F 4C C8 69 C1 97 75 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x359 = { 41 5D 41 5E 41 5F C3 CC CC CC CC CC CC CC CC 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 29 files
		$x45 = "    <requestedEx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 20 files
		$x47 = { 00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 6C } //This might be a string? Looks like:Internal
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8522170014624826 Found in 16 files
		$x362 = { 00 C7 44 24 20 00 00 00 00 31 D2 45 31 C0 45 31 } //This might be a string? Looks like:D$ 1E1E1
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 16 files
		$x364 = { 41 54 56 57 55 53 48 83 EC 48 0F 29 74 24 30 48 } //This might be a string? Looks like:ATVWUSHH)t$0H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 46 files
		$x53 = "SystemTimeAsFile" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 38 files
		$x370 = { AF 70 AF 80 AF 90 AF A0 AF B0 AF C0 AF D0 AF E0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 14 files
		$x498 = { 02 00 48 8B E8 48 8D 48 01 48 83 F9 01 76 2D 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8993974703476995 Found in 18 files
		$x371 = { 41 5F C3 CC 41 57 41 56 41 55 41 54 56 57 55 53 } //This might be a string? Looks like:A_AWAVAUATVWUS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 15 files
		$x373 = { 0B 50 0A 70 09 60 08 C0 06 D0 04 E0 02 F0 01 15 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 13 files
		$x375 = { 08 00 0E 92 0A 30 09 50 08 70 07 60 06 C0 04 E0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 12 files
		$x56 = { CC CC CC CC CC CC CC CC CC CC 56 57 48 83 EC 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 19 files
		$x2 = { 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 } //This might be a string? Looks like:iginalFi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 26 files
		$x378 = { 90 A3 98 A3 A0 A3 A8 A3 B0 A3 B8 A3 C0 A3 C8 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 26 files
		$x3 = { 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 } //This might be a string? Looks like:gFileInf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.311278124459133 Found in 18 files
		$x60 = { 48 8B 44 24 40 48 8B 44 24 40 48 8B 44 24 40 48 } //This might be a string? Looks like:HD$@HD$@HD$@H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.077819531114783 Found in 12 files
		$x379 = { 00 40 00 00 40 2E 64 61 74 61 00 00 00 00 40 00 } //This might be a string? Looks like:@@.data@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8584585933443494 Found in 15 files
		$x62 = { 44 24 30 48 8B 44 24 30 48 8B 00 48 89 44 24 38 } //This might be a string? Looks like:D$0HD$0HHD$8
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 18 files
		$x5 = { 6E 00 74 00 65 00 72 00 6E 00 61 00 6C 00 4E 00 } //This might be a string? Looks like:nternalN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 29 files
		$x65 = "Vlogic_error@std" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 15 files
		$x380 = { 10 E2 0C 30 0B 70 0A 60 09 C0 07 D0 05 E0 03 F0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.349601752714581 Found in 9 files
		$x381 = { 50 02 B8 00 00 00 00 01 04 01 00 04 82 00 00 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 30 files
		$x68 = { C8 A5 D0 A5 D8 A5 E0 A5 E8 A5 F0 A5 F8 A5 00 A6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 16 files
		$x383 = { 69 00 6C 00 65 00 2D 00 6C 00 32 00 2D 00 31 00 } //This might be a string? Looks like:ile-l2-1
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 10 files
		$x384 = { 0D 60 0C C0 0A E0 08 F0 06 50 22 05 93 19 01 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 22 files
		$x69 = { 00 AC 08 AC 10 AC 18 AC 20 AC 28 AC 30 AC 38 AC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 14 files
		$x71 = { 74 65 43 6F 6D 70 61 74 69 62 6C 65 44 43 00 00 } //This might be a string? Looks like:teCompatibleDC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.091917186688699 Found in 12 files
		$x388 = { 5B 5F 5E 41 5E 5D C3 CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 27 files
		$x10 = { 65 6D 62 6C 79 20 78 6D 6C 6E 73 3D 22 75 72 6E } //This might be a string? Looks like:embly xmlns="urn
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 16 files
		$x11 = "ntime.(*workbuf)" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 12 files
		$x74 = { 3B 63 73 6D E0 74 23 44 39 03 75 10 83 7B 18 0F } //This might be a string? Looks like:;csmt#D9u{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 10 files
		$x389 = { D1 80 F2 01 89 C3 30 D3 20 C3 20 C2 08 CA 89 D8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 17 files
		$x75 = { B8 00 10 00 00 41 B9 04 00 00 00 FF D0 48 89 84 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x77 = { C0 10 48 89 44 24 38 48 8B 44 24 38 48 8B 00 48 } //This might be a string? Looks like:HD$8HD$8HH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 11 files
		$x79 = { 03 0C 22 08 30 07 70 06 60 05 E0 03 F0 01 50 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 14 files
		$x391 = { 0B 00 15 68 04 00 10 A2 0C 30 0B 50 0A 70 09 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x393 = { 50 A1 58 A1 60 A1 68 A1 70 A1 78 A1 80 A1 88 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 19 files
		$x12 = "SetEnvironmentVa" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 15 files
		$x81 = { 50 00 00 CC CC CC 48 83 EC 28 48 85 C9 75 17 E8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 19 files
		$x82 = { 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 } //This might be a string? Looks like:ding="UTF-8" sta
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.271782221599798 Found in 22 files
		$x86 = { 5C 41 5D 41 5E 41 5F C3 CC CC CC CC CC CC CC 41 } //This might be a string? Looks like:\A]A^A_A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 11 files
		$x87 = { 8D 50 FF 0F AF D0 F6 C2 01 0F 94 45 FE 83 F9 0A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 15 files
		$x396 = { 00 19 32 15 E0 01 14 08 00 14 64 09 00 14 54 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 17 files
		$x89 = { 00 00 00 48 8D 65 08 5B 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like:He[_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 10 files
		$x90 = { 01 00 0F 83 C3 03 00 00 49 8B C5 8D 56 01 83 E0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 39 files
		$x18 = { A7 D0 A7 E0 A7 F0 A7 00 A8 10 A8 20 A8 30 A8 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5306390622295665 Found in 26 files
		$x92 = { 00 00 55 55 55 55 55 55 D5 3F 00 00 00 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 15 files
		$x93 = { FF 48 8B 44 24 28 48 8B 00 48 8B 4C 24 28 FF 50 } //This might be a string? Looks like:HD$(HHL$(P
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 15 files
		$x400 = { 74 72 69 6E 67 20 70 6F 73 69 74 69 6F 6E 00 69 } //This might be a string? Looks like:tring positioni
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1556390622295662 Found in 14 files
		$x94 = { 31 E0 48 89 44 24 40 48 89 4C 24 28 48 8B 44 24 } //This might be a string? Looks like:1HD$@HL$(HD$
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 19 files
		$x403 = { A2 48 A2 50 A2 58 A2 60 A2 68 A2 70 A2 78 A2 80 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 20 files
		$x404 = { 38 A2 40 A2 48 A2 50 A2 58 A2 60 A2 68 A2 70 A2 } //This might be a string? Looks like:8@HPX`hp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 23 files
		$x405 = { D8 A7 E8 A7 F8 A7 08 A8 18 A8 28 A8 38 A8 48 A8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 22 files
		$x24 = { 00 01 00 56 00 61 00 72 00 46 00 69 00 6C 00 65 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.521782221599798 Found in 16 files
		$x407 = { 00 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 40 00 81 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 18 files
		$x104 = { 24 40 48 83 C4 58 5B 5D 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like:$@HX[]_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 12 files
		$x105 = { 75 14 48 FF C1 EB 0F 0F B6 01 4A 0F BE 84 00 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 15 files
		$x410 = { 28 75 F0 48 8D 65 08 5B 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like:(uHe[_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 41 files
		$x34 = "amily not suppor" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x110 = { 83 E2 01 F7 DA 81 E2 DF B0 08 99 33 91 34 06 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.25 Found in 15 files
		$x411 = { 00 00 46 6C 73 47 65 74 56 61 6C 75 65 32 00 00 } //This might be a string? Looks like:FlsGetValue2
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 19 files
		$x111 = { AC B0 AC B8 AC C0 AC C8 AC D0 AC D8 AC E0 AC E8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 17 files
		$x412 = { 20 89 F0 48 8D 65 08 5B 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like: He[_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 26 files
		$x115 = { A9 B0 A9 B8 A9 C0 A9 C8 A9 D0 A9 D8 A9 E0 A9 E8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 24 files
		$x116 = { 00 80 30 31 32 33 34 35 36 37 38 39 61 62 63 64 } //This might be a string? Looks like:0123456789abcd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 9 files
		$x413 = { F2 01 89 D3 20 CB 80 F1 01 20 C8 08 D8 89 CB 20 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 9 files
		$x118 = { AF D0 F6 C2 01 0F 94 45 FA 83 F9 0A 0F 9C 45 FB } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 11 files
		$x120 = { 06 00 8D 68 FF 0F AF E8 40 F6 C5 01 0F 94 44 24 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 26 files
		$x41 = "tionLevel level=" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 27 files
		$x121 = "operation would " ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 12 files
		$x122 = "PolicyGetThreadI" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 9 files
		$x415 = { 02 00 F6 42 38 20 74 B8 33 D2 41 8B CA 44 8D 42 } //This might be a string? Looks like:B8 t3ADB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 17 files
		$x43 = { 0A 2B 06 01 04 01 82 37 02 01 0F 30 09 03 01 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 17 files
		$x124 = { FE FF FF 48 8B 74 24 30 48 8B 4C 24 38 48 31 E1 } //This might be a string? Looks like:Ht$0HL$8H1
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 17 files
		$x46 = { 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 } //This might be a string? Looks like:kernel32.dll
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 15 files
		$x416 = { 83 C4 20 4C 89 F0 48 8D 65 08 5B 5F 5E 41 5C 41 } //This might be a string? Looks like: LHe[_^A\A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 9 files
		$x417 = { 72 65 6E 74 54 68 72 65 61 64 49 64 00 00 61 02 } //This might be a string? Looks like:rentThreadIda
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 12 files
		$x418 = { 13 01 1D 00 0C 30 0B 70 0A 60 09 C0 07 D0 05 E0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x127 = { 64 65 63 6C 00 5F 5F 70 61 73 63 61 6C 00 00 00 } //This might be a string? Looks like:decl__pascal
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 21 files
		$x129 = { 02 00 0F B7 04 58 83 E0 01 48 8B 5C 24 30 48 83 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6737949406953985 Found in 12 files
		$x419 = { CC CC CC CC CC CC CC CC CC CC 55 41 57 41 56 56 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 20 files
		$x130 = { 5E 41 5F C3 CC CC CC CC CC CC CC CC 55 41 57 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.25 Found in 9 files
		$x131 = { 48 83 C4 20 48 8B 03 48 83 EC 20 48 89 D9 FF 50 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 18 files
		$x132 = { A8 AC B0 AC B8 AC C0 AC C8 AC D0 AC D8 AC E0 AC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 20 files
		$x133 = { 6E 66 6F 3E 0D 0A 3C 2F 61 73 73 65 6D 62 6C 79 } //This might be a string? Looks like:nfo>\r\n</assembly
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 26 files
		$x134 = { 20 44 4F 53 20 6D 6F 64 65 2E 24 00 00 50 45 00 } //This might be a string? Looks like: DOS mode.$PE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 13 files
		$x421 = { 10 09 00 10 42 0C 30 0B 50 0A 70 09 60 08 C0 06 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 9 files
		$x422 = { 80 F2 01 30 C8 80 F1 01 08 D1 89 CA 30 C2 A8 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 10 files
		$x423 = { 00 00 61 02 47 65 74 45 6E 76 69 72 6F 6E 6D 65 } //This might be a string? Looks like:aGetEnvironme
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6493974703476995 Found in 20 files
		$x137 = { 41 5E 41 5F C3 CC CC CC CC 55 41 57 41 56 41 55 } //This might be a string? Looks like:A^A_UAWAVAU
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4966407621868583 Found in 18 files
		$x140 = { CC CC CC CC CC CC CC CC CC CC CC 41 56 56 57 55 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x425 = { 49 6E 66 6F 57 00 00 A0 02 47 65 74 4D 6F 64 75 } //This might be a string? Looks like:InfoWGetModu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 16 files
		$x143 = { 41 54 56 57 53 48 83 EC 38 48 8D 6C 24 30 48 8B } //This might be a string? Looks like:ATVWSH8Hl$0H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 9 files
		$x426 = { 95 C0 41 83 F8 0A 0F 9C C2 41 83 F8 09 0F 9F C3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6556390622295662 Found in 27 files
		$x148 = { 48 89 84 24 88 00 00 00 48 8B 84 24 C8 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 12 files
		$x428 = { FD 80 7D F0 00 74 0F 8B 5D EC 48 8D 4D C0 E8 62 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 10 files
		$x149 = { A0 20 A1 50 A1 80 A1 B0 A1 E0 A1 10 A2 40 A2 70 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 13 files
		$x150 = { 8B 00 48 89 44 24 30 48 83 7C 24 30 00 0F 95 44 } //This might be a string? Looks like:HD$0H|$0D
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.271782221599798 Found in 17 files
		$x151 = { 41 5E 41 5F C3 CC CC CC CC CC CC CC 55 41 57 41 } //This might be a string? Looks like:A^A_UAWA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 25 files
		$x153 = { 64 50 72 69 76 69 6C 65 67 65 73 3E 0D 0A 20 20 } //This might be a string? Looks like:dPrivileges>\r\n  
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 9 files
		$x155 = { 00 8D 50 FF 0F AF D0 F6 C2 01 0F 94 44 24 2E 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 11 files
		$x156 = { 00 40 00 00 40 2E 64 61 74 61 00 00 00 00 50 00 } //This might be a string? Looks like:@@.dataP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7806390622295662 Found in 9 files
		$x432 = { 75 11 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 44 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x433 = { 9C C1 83 F8 09 0F 9F C0 20 C3 20 D1 08 D9 89 C3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 9 files
		$x161 = { C2 83 F8 0A 0F 9C C0 0F 9C 44 24 27 08 D0 41 B8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 14 files
		$x163 = { CC CC CC CC CC CC CC CC CC CC 56 48 83 EC 30 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 30 files
		$x164 = { A3 F0 A3 F8 A3 00 A4 08 A4 10 A4 18 A4 20 A4 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 15 files
		$x434 = { C3 8B C3 48 83 C4 20 5B C3 CC 48 89 5C 24 08 57 } //This might be a string? Looks like:H [H\$W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 10 files
		$x166 = { 20 80 7D F8 00 74 0F 8B 5D F4 48 8D 4D C0 E8 19 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 33 files
		$x167 = "DEFGHIJKLMNOPQRS" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6556390622295662 Found in 17 files
		$x435 = { CC CC CC CC CC CC 55 41 57 41 56 56 57 53 48 83 } //This might be a string? Looks like:UAWAVVWSH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.646782221599798 Found in 17 files
		$x436 = { 41 5D 41 5E 41 5F C3 CC CC 41 57 41 56 41 55 41 } //This might be a string? Looks like:A]A^A_AWAVAUA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 17 files
		$x21 = "too many argumen" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.73345859334435 Found in 13 files
		$x170 = { 14 54 0D 00 14 34 0C 00 14 92 10 70 00 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9197367178034823 Found in 20 files
		$x171 = { 5E 41 5F C3 CC CC CC CC CC CC CC CC CC 41 57 41 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 18 files
		$x28 = { 16 06 03 55 1D 25 01 01 FF 04 0C 30 0A 06 08 2B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 16 files
		$x172 = { 00 01 13 0A 00 13 01 11 00 0C 30 0B 50 0A 70 09 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 18 files
		$x173 = { AB 38 AB 40 AB 48 AB 50 AB 58 AB 60 AB 68 AB 70 } //This might be a string? Looks like:8@HPX`hp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 30 files
		$x174 = { 28 A4 30 A4 38 A4 40 A4 48 A4 50 A4 58 A4 60 A4 } //This might be a string? Looks like:(08@HPX`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 18 files
		$x175 = { CC CC CC CC CC CC 48 8D 41 10 0F B6 CA 48 89 C2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 22 files
		$x176 = { 10 AF 18 AF 20 AF 28 AF 30 AF 38 AF 40 AF 48 AF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 26 files
		$x178 = { 6E 64 69 74 69 6F 6E 56 61 72 69 61 62 6C 65 00 } //This might be a string? Looks like:nditionVariable
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 17 files
		$x38 = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 21 files
		$x438 = { C0 A0 C8 A0 D0 A0 D8 A0 E0 A0 E8 A0 F0 A0 F8 A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 14 files
		$x182 = { 48 89 EC 5B 5F 5E 41 5C 41 5E 41 5F 5D C3 CC CC } //This might be a string? Looks like:H[_^A\A^A_]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 11 files
		$x183 = { 02 00 48 29 C4 48 89 E0 48 89 45 A8 B8 10 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 34 files
		$x184 = "WideCharToMultiB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 28 files
		$x185 = { 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 } //This might be a string? Looks like:XYZ[\]^_`abcdefg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 23 files
		$x440 = { 40 A1 48 A1 50 A1 58 A1 60 A1 68 A1 70 A1 78 A1 } //This might be a string? Looks like:@HPX`hpx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7334585933443494 Found in 22 files
		$x188 = { 41 5C 41 5D 41 5E 41 5F C3 CC CC CC 41 57 41 56 } //This might be a string? Looks like:A\A]A^A_AWAV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.646782221599798 Found in 13 files
		$x189 = { 83 C4 48 5B 5F 5E 41 5E C3 CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 22 files
		$x190 = { AD 88 AD 90 AD 98 AD A0 AD A8 AD B0 AD B8 AD C0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 16 files
		$x191 = { FF FF 48 8B 74 24 28 48 8B 4C 24 38 48 31 E1 E8 } //This might be a string? Looks like:Ht$(HL$8H1
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.125 Found in 15 files
		$x442 = { CC CC CC CC CC CC CC CC 55 41 57 41 56 56 57 53 } //This might be a string? Looks like:UAWAVVWS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 23 files
		$x193 = { 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 } //This might be a string? Looks like:.0" encoding="UT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5306390622295662 Found in 25 files
		$x199 = { 72 63 61 6C 6C 00 00 00 00 5F 5F 63 6C 72 63 61 } //This might be a string? Looks like:rcall__clrca
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.3244602933016414 Found in 23 files
		$x443 = { CC CC CC CC CC CC CC CC CC CC CC 48 83 EC 48 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 18 files
		$x202 = { 74 11 48 8D 4B F0 81 39 DD DD 00 00 75 05 E8 1E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7272170014624826 Found in 26 files
		$x203 = { FF FF FF 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 44 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 36 files
		$x204 = { 10 A0 20 A0 30 A0 40 A0 50 A0 60 A0 70 A0 80 A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 21 files
		$x50 = "GetFileAttribute" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 9 files
		$x444 = { 41 83 F8 09 0F 9F C2 41 83 F8 0A 0F 9C C3 0F 9C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 32 files
		$x205 = { 6C 56 69 72 74 75 61 6C 55 6E 77 69 6E 64 00 00 } //This might be a string? Looks like:lVirtualUnwind
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 21 files
		$x445 = { A0 D0 A0 D8 A0 E0 A0 E8 A0 F0 A0 F8 A0 00 A1 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 12 files
		$x206 = { 41 55 41 54 56 57 55 53 48 81 EC 98 00 00 00 49 } //This might be a string? Looks like:AUATVWUSHI
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 9 files
		$x208 = { 50 FF 0F AF D0 F6 C2 01 0F 94 C0 0F 94 44 24 2E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 21 files
		$x447 = { D0 A2 D8 A2 E0 A2 E8 A2 F0 A2 F8 A2 00 A3 08 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 12 files
		$x211 = { 8D 65 38 5B 5F 5E 41 5C 41 5D 41 5E 41 5F 5D C3 } //This might be a string? Looks like:e8[_^A\A]A^A_]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 20 files
		$x212 = { CC CC CC CC CC CC CC CC 56 57 55 53 48 83 EC 38 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 21 files
		$x213 = { 55 41 54 56 57 53 48 83 EC 68 48 8D 6C 24 60 48 } //This might be a string? Looks like:UATVWSHhHl$`H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6216407621868583 Found in 19 files
		$x448 = { 83 C4 40 5D C3 CC CC CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 11 files
		$x449 = { 00 79 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 } //This might be a string? Looks like:yCreateWindowE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x217 = { FF 0F AF F0 40 F6 C6 01 0F 94 44 24 2E 83 F9 0A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 9 files
		$x218 = { 00 0E B2 0A 30 09 50 08 70 07 60 06 C0 04 E0 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8584585933443494 Found in 16 files
		$x219 = { 4C 24 28 48 8B 44 24 28 48 89 44 24 30 48 8B 44 } //This might be a string? Looks like:L$(HD$(HD$0HD
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 18 files
		$x450 = { 69 73 70 61 74 63 68 4D 65 73 73 61 67 65 57 00 } //This might be a string? Looks like:ispatchMessageW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 29 files
		$x223 = { 6B 6E 6F 77 6E 20 65 78 63 65 70 74 69 6F 6E 00 } //This might be a string? Looks like:known exception
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 14 files
		$x453 = { 08 00 14 54 07 00 14 34 06 00 14 32 10 70 01 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x226 = { 74 0C 48 85 D2 74 07 4D 85 C0 75 1B 88 19 E8 56 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 24 files
		$x227 = { 75 4F F6 C1 C0 74 4A 8B 3B 2B 7B 08 83 63 10 00 } //This might be a string? Looks like:uOtJ;+{c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.091917186688699 Found in 13 files
		$x228 = { CC CC CC CC CC CC CC CC CC 56 48 83 EC 40 48 8B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.875 Found in 16 files
		$x229 = { 48 89 84 24 E8 02 00 00 48 8B 84 24 E8 02 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 15 files
		$x230 = { 57 55 53 48 83 EC 38 4C 89 C6 48 89 D7 48 89 CB } //This might be a string? Looks like:WUSH8LHH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 21 files
		$x231 = { 00 48 89 F0 48 83 C4 38 5B 5D 5F 5E C3 CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 13 files
		$x457 = { 00 A3 02 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 } //This might be a string? Looks like:GetModuleHand
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8522170014624826 Found in 17 files
		$x234 = { E9 5E FF FF FF 66 2E 0F 1F 84 00 00 00 00 00 0F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 14 files
		$x235 = { 83 EC 30 8A DA 48 8B 41 40 48 8B 78 08 48 89 7C } //This might be a string? Looks like:0HA@HxH|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 17 files
		$x458 = { 83 C4 20 5D C3 40 55 48 83 EC 20 48 8B EA 48 8B } //This might be a string? Looks like: ]@UH HH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6493974703476995 Found in 10 files
		$x236 = { 41 5C 41 5D 41 5E 41 5F 5D C3 CC CC CC CC CC 56 } //This might be a string? Looks like:A\A]A^A_]V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 11 files
		$x241 = { 81 EC B8 00 00 00 48 8D AC 24 80 00 00 00 0F 29 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 10 files
		$x246 = { 41 57 41 56 56 57 55 53 48 83 EC 38 48 89 D6 48 } //This might be a string? Looks like:AWAVVWUSH8HH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7334585933443494 Found in 16 files
		$x247 = { 20 48 8B 44 24 20 48 89 44 24 28 48 8B 44 24 28 } //This might be a string? Looks like: HD$ HD$(HD$(
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 10 files
		$x459 = { 19 15 07 00 11 42 0D 30 0C 70 0B 60 0A E0 08 F0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 9 files
		$x460 = { 48 83 EC 58 48 8D 6C 24 50 48 C7 45 00 FE FF FF } //This might be a string? Looks like:HXHl$PHE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.186278124459133 Found in 22 files
		$x250 = { CC CC CC CC CC CC CC CC CC CC CC CC 41 56 56 57 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 21 files
		$x251 = { 6E 00 69 6F 73 74 72 65 61 6D 00 62 61 64 20 61 } //This might be a string? Looks like:niostreambad a
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 27 files
		$x252 = { 00 00 20 54 79 70 65 20 44 65 73 63 72 69 70 74 } //This might be a string? Looks like: Type Descript
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 9 files
		$x253 = { CC 48 83 EC 28 33 D2 48 8D 4C 24 30 E8 C8 FA FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 32 files
		$x254 = { 70 A4 78 A4 80 A4 88 A4 90 A4 98 A4 A0 A4 A8 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 25 files
		$x255 = "mbuf@DU?$char_tr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 30 files
		$x257 = { 48 00 48 00 3A 00 6D 00 6D 00 3A 00 73 00 73 00 } //This might be a string? Looks like:HH:mm:ss
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 43 files
		$x29 = "nnection refused" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 14 files
		$x258 = { CC CC CC CC CC CC CC CC 56 48 83 EC 30 48 8B 05 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 13 files
		$x262 = "reeLibraryAndExi" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 42 files
		$x33 = "ly not supported" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 34 files
		$x264 = { 40 AC 50 AC 60 AC 70 AC 80 AC 90 AC A0 AC B0 AC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 18 files
		$x265 = { 0E 12 0A 30 09 70 08 60 07 C0 05 E0 03 F0 01 50 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 34 files
		$x266 = { 00 00 00 00 00 20 00 00 60 2E 72 64 61 74 61 00 } //This might be a string? Looks like: `.rdata
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 16 files
		$x465 = { 01 15 00 0C 30 0B 50 0A 70 09 60 08 C0 06 D0 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 12 files
		$x268 = { 00 00 48 29 C4 48 89 E0 48 89 45 D0 B8 10 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 10 files
		$x269 = { 94 C0 0F 94 45 FE 83 F9 0A 0F 9C C1 0F 9C 45 FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.60845859334435 Found in 10 files
		$x270 = { 46 30 00 00 48 C7 46 38 00 00 00 00 66 C7 46 40 } //This might be a string? Looks like:F0HF8fF@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 39 files
		$x40 = "ueryPerformanceC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 18 files
		$x467 = { 20 89 D8 48 8D 65 08 5B 5F 5E 41 5C 41 5D 41 5E } //This might be a string? Looks like: He[_^A\A]A^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4966407621868583 Found in 20 files
		$x468 = { FF FF CC CC CC CC CC CC CC CC CC CC CC 48 83 EC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 38 files
		$x275 = { 10 A5 20 A5 30 A5 40 A5 50 A5 60 A5 70 A5 80 A5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 9 files
		$x470 = { 56 57 53 48 83 EC 28 48 8D AA 80 00 00 00 48 8D } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 26 files
		$x277 = { F5 F6 F7 F8 F9 FA FB FC FD FE FF 00 00 20 00 20 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 25 files
		$x278 = { 00 00 00 00 60 73 63 61 6C 61 72 20 64 65 6C 65 } //This might be a string? Looks like:`scalar dele
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 19 files
		$x472 = { 98 A2 A0 A2 A8 A2 B0 A2 B8 A2 C0 A2 C8 A2 D0 A2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.311278124459133 Found in 17 files
		$x281 = { 30 48 8B 44 24 30 48 8B 44 24 30 48 8B 44 24 30 } //This might be a string? Looks like:0HD$0HD$0HD$0
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 27 files
		$x282 = "123456789abcdefg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 31 files
		$x284 = { 8B 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 18 files
		$x49 = { 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.875 Found in 14 files
		$x286 = { 10 48 89 44 24 40 48 8B 44 24 40 48 8B 00 48 89 } //This might be a string? Looks like:HD$@HD$@HH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 17 files
		$x287 = { 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E } //This might be a string? Looks like:name="Microsoft.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 26 files
		$x288 = { A7 08 A8 18 A8 28 A8 38 A8 48 A8 58 A8 68 A8 78 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 36 files
		$x290 = { 60 A9 70 A9 80 A9 90 A9 A0 A9 B0 A9 C0 A9 D0 A9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.646782221599798 Found in 12 files
		$x293 = { 89 F0 48 83 C4 48 5F 5E C3 CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 10 files
		$x476 = { 20 C2 80 F2 01 89 C3 30 D3 08 C2 80 F2 01 08 DA } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.202819531114783 Found in 22 files
		$x294 = { 00 00 00 00 00 00 00 5F 5F 70 74 72 36 34 00 5F } //This might be a string? Looks like:__ptr64_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 24 files
		$x477 = { 88 A3 90 A3 98 A3 A0 A3 A8 A3 B0 A3 B8 A3 C0 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 18 files
		$x296 = { 03 13 01 11 00 0C 30 0B 70 0A 60 09 C0 07 D0 05 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 31 files
		$x298 = { 80 A4 88 A4 90 A4 98 A4 A0 A4 A8 A4 B0 A4 B8 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 12 files
		$x300 = { 54 56 57 53 48 83 EC 68 48 8D 6C 24 60 48 8B 05 } //This might be a string? Looks like:TVWSHhHl$`H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 26 files
		$x301 = { 01 45 6E 75 6D 53 79 73 74 65 6D 4C 6F 63 61 6C } //This might be a string? Looks like:EnumSystemLocal
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 11 files
		$x302 = { 00 01 10 09 00 10 62 0C 30 0B 50 0A 70 09 60 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 9 files
		$x303 = { 8B 44 24 28 48 8B 00 48 63 40 04 48 8B 4C 24 20 } //This might be a string? Looks like:D$(HHc@HL$ 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 27 files
		$x304 = { C8 A3 D8 A3 E8 A3 F8 A3 08 A4 18 A4 28 A4 38 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 24 files
		$x307 = { 70 74 69 6F 6E 00 69 6E 76 61 6C 69 64 20 73 74 } //This might be a string? Looks like:ptioninvalid st
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 15 files
		$x308 = { 54 56 57 55 53 48 83 EC 48 0F 29 74 24 30 48 8B } //This might be a string? Looks like:TVWUSHH)t$0H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 11 files
		$x309 = { 20 57 48 83 EC 40 49 8B F9 49 8B D8 8B 0A E8 24 } //This might be a string? Looks like: WH@II\n$
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x310 = { 6C 6F 6E 65 3D 22 79 65 73 22 3F 3E 0D 0A 3C 21 } //This might be a string? Looks like:lone="yes"?>\r\n<!
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 37 files
		$x312 = { A3 D0 A3 E0 A3 F0 A3 00 A4 10 A4 20 A4 30 A4 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 26 files
		$x314 = { 00 00 00 60 64 79 6E 61 6D 69 63 20 69 6E 69 74 } //This might be a string? Looks like:`dynamic init
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 15 files
		$x317 = { 00 48 29 C4 48 89 E0 48 89 45 A0 B8 10 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 28 files
		$x319 = { F8 F9 FA FB FC FD FE FF 80 81 82 83 84 85 86 87 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 11 files
		$x320 = { 89 74 24 28 48 8B 44 24 28 48 89 44 24 30 48 8B } //This might be a string? Looks like:t$(HD$(HD$0H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.271782221599798 Found in 20 files
		$x323 = { 41 5E 41 5F C3 CC CC CC CC CC CC CC 41 57 41 56 } //This might be a string? Looks like:A^A_AWAV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 30 files
		$x326 = { C8 A4 D0 A4 D8 A4 E0 A4 E8 A4 F0 A4 F8 A4 00 A5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 15 files
		$x483 = { 4C 89 F0 48 83 C4 38 5B 5D 5F 5E 41 5C 41 5D 41 } //This might be a string? Looks like:LH8[]_^A\A]A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 21 files
		$x329 = { 5F C3 CC CC CC CC CC CC CC CC CC CC 41 57 41 56 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 17 files
		$x20 = { 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 14 files
		$x485 = { 0F 10 01 41 0F 11 07 48 83 EC 40 48 89 44 24 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 9 files
		$x486 = { CA 20 C3 08 D3 89 CA 20 C2 30 C1 08 D1 89 CA 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2806390622295662 Found in 12 files
		$x332 = { 48 8B 44 24 28 48 8B 4C 24 30 8B 09 8D 51 01 48 } //This might be a string? Looks like:HD$(HL$0\tQH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 37 files
		$x333 = "tCurrentThreadId" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 11 files
		$x334 = { 00 48 63 40 04 48 8B 4C 24 28 48 8B 44 01 50 48 } //This might be a string? Looks like:Hc@HL$(HDPH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 22 files
		$x335 = { F8 AB 00 AC 08 AC 10 AC 18 AC 20 AC 28 AC 30 AC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 25 files
		$x336 = { F8 3D CA 1C C8 25 88 52 10 3E 6A 74 6D 7D 53 95 } //This might be a string? Looks like:=%R>jtm}S
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 14 files
		$x488 = { 74 43 6F 6E 73 6F 6C 65 4D 6F 64 65 00 00 28 02 } //This might be a string? Looks like:tConsoleMode(
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 30 files
		$x338 = { A2 88 A2 98 A2 A8 A2 B8 A2 C8 A2 D8 A2 E8 A2 F8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.311278124459133 Found in 16 files
		$x490 = { 5D C3 CC CC CC CC CC CC CC CC CC CC CC CC 41 57 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 22 files
		$x342 = { 00 48 89 F0 48 83 C4 68 5B 5D 5F 5E 41 5C 41 5D } //This might be a string? Looks like:HHh[]_^A\A]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 24 files
		$x343 = { 27 00 60 6D 61 6E 61 67 65 64 20 76 65 63 74 6F } //This might be a string? Looks like:'`managed vecto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 17 files
		$x493 = { 03 00 48 85 DB 48 8B 5C 24 38 74 09 48 8B 07 48 } //This might be a string? Looks like:HH\$8t\tHH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 21 files
		$x347 = { CC CC CC CC CC CC CC CC CC CC 41 56 56 57 53 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 12 files
		$x494 = { 00 9C 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 E5 } //This might be a string? Looks like:CloseHandle
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 20 files
		$x349 = { 10 A6 18 A6 20 A6 28 A6 30 A6 38 A6 40 A6 48 A6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 11 files
		$x350 = { 28 48 8B 00 48 63 40 04 48 03 44 24 20 48 89 44 } //This might be a string? Looks like:(HHc@HD$ HD
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6216407621868583 Found in 20 files
		$x351 = { 5E 41 5F C3 CC CC CC CC CC CC CC CC CC CC CC 55 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 27 files
		$x352 = { 43 6F 6D 70 61 72 65 53 74 72 69 6E 67 45 78 00 } //This might be a string? Looks like:CompareStringEx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.771782221599798 Found in 37 files
		$x353 = { A1 00 A2 10 A2 20 A2 30 A2 40 A2 50 A2 60 A2 70 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 29 files
		$x355 = { B0 75 C6 DB A9 14 B9 D9 E2 DF 72 0F 65 4C 4B 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 9 files
		$x495 = { FF 0F 95 C2 0F 94 C3 83 F8 0A 0F 9C C1 83 F8 09 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 38 files
		$x360 = { A8 D0 A8 E0 A8 F0 A8 00 A9 10 A9 20 A9 30 A9 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 9 files
		$x496 = { 41 56 41 54 56 57 53 48 83 EC 40 48 8D 6C 24 40 } //This might be a string? Looks like:AVATVWSH@Hl$@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 17 files
		$x361 = { 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 48 89 } //This might be a string? Looks like:WAVAUATVWUSHH
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 22 files
		$x497 = { A3 78 A3 80 A3 88 A3 90 A3 98 A3 A0 A3 A8 A3 B0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 21 files
		$x363 = { AC F0 AC F8 AC 00 AD 08 AD 10 AD 18 AD 20 AD 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 20 files
		$x365 = { AC 88 AC 90 AC 98 AC A0 AC A8 AC B0 AC B8 AC C0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 32 files
		$x366 = { 88 A5 90 A5 98 A5 A0 A5 A8 A5 B0 A5 B8 A5 C0 A5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 28 files
		$x367 = { A9 D8 A9 E0 A9 E8 A9 F0 A9 F8 A9 00 AA 08 AA 10 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 27 files
		$x368 = { 03 49 6E 69 74 69 61 6C 69 7A 65 53 4C 69 73 74 } //This might be a string? Looks like:InitializeSList
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 30 files
		$x369 = { E8 A3 F8 A3 08 A4 18 A4 28 A4 38 A4 48 A4 58 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 17 files
		$x55 = { 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 50 45 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9772170014624826 Found in 36 files
		$x372 = { B0 AC C0 AC D0 AC E0 AC F0 AC 00 AD 10 AD 20 AD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.474601752714581 Found in 37 files
		$x374 = { 00 00 00 A0 10 A0 20 A0 30 A0 40 A0 50 A0 60 A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 19 files
		$x376 = { 00 48 89 F0 48 83 C4 38 5B 5D 5F 5E 41 5E 41 5F } //This might be a string? Looks like:HH8[]_^A^A_

		condition:
(36 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55) ) or (301 of ($x0,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x7,$x67,$x68,$x69,$x70,$x71,$x72,$x10,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83,$x84,$x85,$x86,$x87,$x88,$x89,$x90,$x18,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x106,$x107,$x108,$x109,$x34,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x48,$x128,$x129,$x130,$x131,$x132,$x133,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x8,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x19,$x168,$x169,$x170,$x171,$x26,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x198,$x199,$x200,$x201,$x202,$x203,$x204,$x205,$x206,$x207,$x52,$x208,$x209,$x210,$x211,$x212,$x213,$x214,$x215,$x216,$x217,$x218,$x219,$x220,$x221,$x222,$x223,$x224,$x225,$x226,$x227,$x228,$x229,$x230,$x231,$x232,$x233,$x234,$x235,$x236,$x237,$x238,$x239,$x240,$x241,$x242,$x243,$x244,$x245,$x15,$x246,$x247,$x248,$x249,$x250,$x251,$x252,$x253,$x254,$x255,$x256,$x257,$x29,$x258,$x259,$x260,$x261,$x262,$x33,$x263,$x264,$x265,$x266,$x267,$x268,$x269,$x270,$x271,$x40,$x272,$x273,$x274,$x275,$x276,$x277,$x278,$x279,$x280,$x281,$x282,$x283,$x284,$x285,$x286,$x287,$x288,$x289,$x290,$x291,$x292,$x293,$x294,$x295,$x296,$x297,$x298,$x299,$x300,$x301,$x302,$x303,$x304,$x305,$x306,$x307,$x308,$x309,$x310,$x311,$x312,$x313,$x314,$x315,$x316,$x17,$x317,$x318,$x319,$x320,$x321,$x322,$x323,$x324,$x325,$x326,$x327,$x328,$x329,$x330,$x331,$x332,$x333,$x334,$x335,$x336,$x337,$x338,$x32,$x339,$x340,$x341,$x342,$x343,$x344,$x345,$x346,$x347,$x348,$x349,$x350,$x351,$x352,$x353,$x354,$x355,$x356,$x357,$x358,$x359,$x360,$x45,$x361,$x362,$x363,$x364,$x365,$x366,$x367,$x53,$x368,$x369,$x370,$x371,$x372,$x373,$x374,$x375,$x376) ) or (257 of ($x0,$x377,$x378,$x58,$x61,$x379,$x380,$x381,$x65,$x382,$x7,$x68,$x383,$x384,$x385,$x386,$x387,$x388,$x389,$x390,$x78,$x391,$x392,$x80,$x393,$x394,$x395,$x83,$x84,$x86,$x396,$x397,$x398,$x399,$x18,$x400,$x91,$x92,$x401,$x402,$x403,$x404,$x405,$x100,$x406,$x407,$x408,$x104,$x106,$x409,$x108,$x410,$x34,$x411,$x112,$x412,$x113,$x116,$x413,$x117,$x119,$x414,$x121,$x415,$x125,$x416,$x417,$x126,$x418,$x48,$x419,$x130,$x420,$x134,$x421,$x135,$x422,$x423,$x137,$x424,$x139,$x141,$x425,$x142,$x144,$x145,$x146,$x426,$x427,$x148,$x428,$x8,$x429,$x152,$x154,$x430,$x157,$x431,$x432,$x159,$x160,$x433,$x162,$x434,$x164,$x165,$x167,$x19,$x435,$x168,$x436,$x437,$x171,$x174,$x175,$x178,$x179,$x438,$x439,$x184,$x185,$x440,$x187,$x441,$x188,$x442,$x194,$x197,$x198,$x199,$x200,$x443,$x202,$x203,$x204,$x444,$x445,$x205,$x52,$x446,$x209,$x210,$x447,$x213,$x448,$x449,$x215,$x450,$x451,$x452,$x223,$x453,$x454,$x455,$x227,$x456,$x231,$x232,$x457,$x458,$x237,$x238,$x239,$x459,$x460,$x250,$x251,$x252,$x254,$x255,$x461,$x462,$x257,$x29,$x463,$x33,$x264,$x265,$x464,$x266,$x465,$x466,$x40,$x467,$x273,$x468,$x274,$x275,$x469,$x470,$x471,$x277,$x472,$x278,$x282,$x283,$x284,$x473,$x285,$x288,$x474,$x475,$x290,$x476,$x294,$x477,$x296,$x298,$x478,$x301,$x304,$x479,$x307,$x480,$x312,$x481,$x314,$x316,$x17,$x319,$x482,$x321,$x323,$x324,$x483,$x325,$x326,$x329,$x484,$x485,$x486,$x487,$x333,$x336,$x488,$x338,$x489,$x32,$x490,$x340,$x491,$x341,$x342,$x343,$x492,$x493,$x345,$x347,$x494,$x351,$x352,$x353,$x354,$x355,$x357,$x359,$x495,$x360,$x496,$x497,$x366,$x53,$x498,$x368,$x369,$x370,$x371,$x372,$x374) )}