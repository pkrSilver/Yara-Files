rule vidar2
{
	//Input TP Rate:
	//35/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.327819531114783 Found in 7 files
		$x32 = { 2A 46 44 29 2E 77 72 69 74 65 43 6F 6E 73 6F 6C 65 00 75 6E 69 63 6F 64 65 2F 75 74 66 38 2E 46 } //This might be a string? Looks like:*FD).writeConsoleunicode/utf8.F
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.101409765557392 Found in 15 files
		$x33 = { 4C 30 17 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 09 03 01 00 A0 04 A2 02 80 00 30 31 30 0D 06 09 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x35 = { 68 A7 70 A7 78 A7 80 A7 88 A7 90 A7 98 A7 A0 A7 A8 A7 B0 A7 B8 A7 C0 A7 C8 A7 D0 A7 D8 A7 E0 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.8164280318460246 Found in 26 files
		$x4 = { 00 00 00 00 60 64 79 6E 61 6D 69 63 20 69 6E 69 74 69 61 6C 69 7A 65 72 20 66 6F 72 20 27 00 00 } //This might be a string? Looks like:`dynamic initializer for '
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.246696364505181 Found in 7 files
		$x40 = { 88 01 00 00 18 A0 20 A0 30 A0 58 A0 60 A0 70 A0 98 A0 A0 A0 B0 A0 D8 A0 E0 A0 F0 A0 18 A1 20 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1686450333085068 Found in 8 files
		$x41 = { F8 A1 00 A2 10 A2 18 A2 28 A2 30 A2 40 A2 48 A2 58 A2 60 A2 70 A2 78 A2 88 A2 90 A2 A0 A2 A8 A2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x43 = { 70 A6 78 A6 80 A6 88 A6 90 A6 98 A6 A0 A6 A8 A6 B0 A6 B8 A6 C0 A6 C8 A6 D0 A6 D8 A6 E0 A6 E8 A6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 29 files
		$x9 = { E7 79 4A E6 FD 22 9A 70 D6 E0 EF CF CA 05 D7 A4 8D BD 6C 00 64 E3 B3 DC 4E A5 6E 08 A8 A1 9E 45 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x47 = { 28 A7 38 A7 40 A7 50 A7 58 A7 68 A7 70 A7 80 A7 88 A7 98 A7 A0 A7 B0 A7 B8 A7 C8 A7 D0 A7 E0 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.944548827786958 Found in 9 files
		$x48 = { 6D 6F 64 75 6C 65 64 61 74 61 76 65 72 69 66 79 31 00 72 75 6E 74 69 6D 65 2E 66 69 6E 64 66 75 } //This might be a string? Looks like:moduledataverify1runtime.findfu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7150182662886326 Found in 10 files
		$x50 = { 6D 61 72 6B 72 6F 6F 74 00 72 75 6E 74 69 6D 65 2E 6D 61 72 6B 72 6F 6F 74 2E 66 75 6E 63 31 00 } //This might be a string? Looks like:markrootruntime.markroot.func1
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3522170014624826 Found in 8 files
		$x51 = { 70 A4 78 A4 B8 A4 C0 A4 D0 A4 D8 A4 18 A5 20 A5 30 A5 38 A5 78 A5 80 A5 90 A5 98 A5 D8 A5 E0 A5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.8042292966721747 Found in 9 files
		$x52 = { 6C 2E 43 72 65 61 74 65 50 72 6F 63 65 73 73 00 73 79 73 63 61 6C 6C 2E 66 6F 72 6D 61 74 4D 65 } //This might be a string? Looks like:l.CreateProcesssyscall.formatMe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 38 files
		$x17 = { A7 D0 A7 E0 A7 F0 A7 00 A8 10 A8 20 A8 30 A8 40 A8 50 A8 60 A8 70 A8 80 A8 90 A8 A0 A8 B0 A8 C0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x53 = { 50 A2 58 A2 60 A2 68 A2 70 A2 78 A2 80 A2 88 A2 90 A2 98 A2 A0 A2 A8 A2 B0 A2 B8 A2 C0 A2 C8 A2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.25 Found in 8 files
		$x56 = { AC B0 AC E0 AC F0 AC 20 AD 30 AD 60 AD 70 AD A0 AD B0 AD E0 AD F0 AD 20 AE 30 AE 60 AE 70 AE A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0519157366363325 Found in 7 files
		$x57 = { 6F 00 65 72 72 6F 72 73 2F 77 72 61 70 2E 67 6F 00 65 72 72 6F 72 73 2F 65 72 72 6F 72 73 2E 67 } //This might be a string? Looks like:oerrors/wrap.goerrors/errors.g
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x59 = { AF 60 AF 68 AF 70 AF 78 AF 80 AF 88 AF 90 AF 98 AF A0 AF A8 AF B0 AF B8 AF C0 AF C8 AF D0 AF D8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.265319531114783 Found in 6 files
		$x62 = { 06 09 05 0C 08 06 07 04 0A 17 09 09 0C 17 0B 1F 0E 10 0D 3B 00 02 0B 10 07 90 01 8E 02 8F 01 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 9 files
		$x63 = { AE A0 AE B0 AE B8 AE C8 AE D0 AE E0 AE E8 AE F8 AE 00 AF 10 AF 18 AF 28 AF 30 AF 40 AF 48 AF 58 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 39 files
		$x24 = { 70 A6 80 A6 90 A6 A0 A6 B0 A6 C0 A6 D0 A6 E0 A6 F0 A6 00 A7 10 A7 20 A7 30 A7 40 A7 50 A7 60 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x64 = { 20 AD 28 AD 30 AD 38 AD 40 AD 48 AD 50 AD 58 AD 60 AD 68 AD 70 AD 78 AD 80 AD 88 AD 90 AD 98 AD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 21 files
		$x66 = { AD A8 AD B0 AD B8 AD C0 AD C8 AD D0 AD D8 AD E0 AD E8 AD F0 AD F8 AD 00 AE 08 AE 10 AE 18 AE 20 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.327819531114783 Found in 10 files
		$x68 = { 89 CA 45 0F 44 C8 45 8D 41 08 85 D2 45 0F 45 C8 84 DB 74 0B 41 0F BA E2 00 73 04 41 83 C9 04 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8285353655857572 Found in 16 files
		$x69 = { 78 A0 80 A0 88 A0 90 A0 98 A0 A0 A0 A8 A0 B0 A0 B8 A0 C0 A0 C8 A0 D0 A0 D8 A0 E0 A0 E8 A0 F0 A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.5 Found in 14 files
		$x70 = { 61 78 00 72 75 6E 74 69 6D 65 2E 28 2A 70 61 67 65 41 6C 6C 6F 63 29 2E 63 68 75 6E 6B 4F 66 00 } //This might be a string? Looks like:axruntime.(*pageAlloc).chunkOf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.804229296672175 Found in 17 files
		$x73 = { 86 F7 0D 01 09 03 31 0C 06 0A 2B 06 01 04 01 82 37 02 01 04 30 1C 06 0A 2B 06 01 04 01 82 37 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.25 Found in 5 files
		$x74 = { 73 73 61 67 65 53 69 7A 65 01 0B 53 79 73 63 61 6C 6C 43 6F 6E 6E 00 0B 2A 6F 73 2E 64 69 72 49 } //This might be a string? Looks like:ssageSizeSyscallConn*os.dirI
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5568497041442484 Found in 8 files
		$x76 = { 9A EB FF FF E8 95 EB FF FF E8 90 EB FF FF E8 8B EB FF FF E8 86 EB FF FF E8 81 EB FF FF E8 7C EB } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x82 = { 20 A4 30 A4 38 A4 48 A4 50 A4 60 A4 68 A4 78 A4 80 A4 90 A4 98 A4 A8 A4 B0 A4 C0 A4 C8 A4 D8 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.6206573285181993 Found in 7 files
		$x87 = { A9 D8 A9 E0 A9 F0 A9 F8 A9 38 AA 40 AA 50 AA 58 AA 98 AA A0 AA B0 AA B8 AA F8 AA 00 AB 10 AB 18 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9650182662886326 Found in 13 files
		$x88 = { 6C 6C 65 72 53 74 61 74 65 29 2E 73 74 61 72 74 43 79 63 6C 65 00 72 75 6E 74 69 6D 65 2E 28 2A } //This might be a string? Looks like:llerState).startCycleruntime.(*
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 35 files
		$x15 = { 60 AC 70 AC 80 AC 90 AC A0 AC B0 AC C0 AC D0 AC E0 AC F0 AC 00 AD 10 AD 20 AD 30 AD 40 AD 50 AD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.1183927290103626 Found in 13 files
		$x90 = { 00 E9 9B FD FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.288909765557392 Found in 13 files
		$x91 = { 2E 62 67 73 63 61 76 65 6E 67 65 00 72 75 6E 74 69 6D 65 2E 28 2A 70 61 67 65 41 6C 6C 6F 63 29 } //This might be a string? Looks like:.bgscavengeruntime.(*pageAlloc)
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.988608500731241 Found in 8 files
		$x93 = { 72 65 73 65 74 4C 69 76 65 00 72 75 6E 74 69 6D 65 2E 28 2A 67 63 43 6F 6E 74 72 6F 6C 6C 65 72 } //This might be a string? Looks like:resetLiveruntime.(*gcController
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 38 files
		$x20 = { AE B0 AE C0 AE D0 AE E0 AE F0 AE 00 AF 10 AF 20 AF 30 AF 40 AF 50 AF 60 AF 70 AF 80 AF 90 AF A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x94 = { AF 08 AF 10 AF 18 AF 20 AF 28 AF 30 AF 38 AF 40 AF 48 AF 50 AF 58 AF 60 AF 68 AF 70 AF 78 AF 80 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.202819531114783 Found in 13 files
		$x95 = { 63 50 61 72 6B 41 73 73 69 73 74 00 72 75 6E 74 69 6D 65 2E 28 2A 67 51 75 65 75 65 29 2E 70 75 } //This might be a string? Looks like:cParkAssistruntime.(*gQueue).pu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 28 files
		$x21 = { ED EE EF F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 80 81 82 83 84 85 86 87 88 89 8A 8B 8C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.3481061300625727 Found in 6 files
		$x97 = { 02 05 02 05 02 07 02 05 02 05 02 05 02 05 02 05 02 07 02 05 02 05 02 05 02 05 02 05 02 07 02 05 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.2386085007312415 Found in 8 files
		$x100 = { 8B 42 08 B9 01 00 00 00 87 08 C3 4C 8D 6C 24 08 66 0F 1F 44 00 00 4D 39 2C 24 75 E3 49 89 24 24 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.852217001462482 Found in 10 files
		$x103 = { 2E 43 6C 6F 73 65 48 61 6E 64 6C 65 00 73 79 73 63 61 6C 6C 2E 43 72 65 61 74 65 46 69 6C 65 4D } //This might be a string? Looks like:.CloseHandlesyscall.CreateFileM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 8 files
		$x108 = { 00 72 75 6E 74 69 6D 65 2E 28 2A 62 6F 75 6E 64 73 45 72 72 6F 72 29 2E 45 72 72 6F 72 00 72 75 } //This might be a string? Looks like:runtime.(*boundsError).Errorru
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9681390622295662 Found in 12 files
		$x111 = "xecutionLevel level='asInvoker' " ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 37 files
		$x0 = { A3 E0 A3 F0 A3 00 A4 10 A4 20 A4 30 A4 40 A4 50 A4 60 A4 70 A4 80 A4 90 A4 A0 A4 B0 A4 C0 A4 D0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.5625 Found in 11 files
		$x112 = { 54 24 18 31 C0 31 DB EB 03 48 FF C0 48 39 D0 7D 33 48 8B 34 C1 83 7E 04 01 75 EE 48 89 44 24 10 } //This might be a string? Looks like:T$11HH9}3H4~uHD$
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.926108500731241 Found in 9 files
		$x113 = { 6E 61 6C 2F 70 6F 6C 6C 2E 28 2A 70 6F 6C 6C 44 65 73 63 29 2E 69 6E 69 74 00 69 6E 74 65 72 6E } //This might be a string? Looks like:nal/poll.(*pollDesc).initintern
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 16 files
		$x114 = { 67 21 A0 FA B3 AB E3 3F 8B 1B CD 4B 78 9A E4 3F 34 9D 98 26 82 84 E5 3F CC 88 47 8E 00 6A E6 3F } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 13 files
		$x119 = { D8 A1 E0 A1 E8 A1 F0 A1 F8 A1 00 A2 08 A2 10 A2 18 A2 20 A2 28 A2 30 A2 38 A2 40 A2 48 A2 50 A2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 30 files
		$x120 = { A4 D8 A4 E0 A4 E8 A4 F0 A4 F8 A4 00 A5 08 A5 10 A5 18 A5 20 A5 28 A5 30 A5 38 A5 40 A5 48 A5 50 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.271782221599798 Found in 7 files
		$x121 = { A8 F8 A8 08 A9 10 A9 20 A9 28 A9 38 A9 40 A9 50 A9 58 A9 68 A9 70 A9 80 A9 88 A9 98 A9 A0 A9 B0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.007048827786958 Found in 9 files
		$x122 = "onStatus failed (errno= runtime:" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x126 = { A1 30 A1 38 A1 48 A1 50 A1 60 A1 68 A1 78 A1 80 A1 90 A1 98 A1 A8 A1 B0 A1 C0 A1 C8 A1 D8 A1 E0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 13 files
		$x128 = { A1 B8 A1 C0 A1 D0 A1 D8 A1 E8 A1 F0 A1 00 A2 08 A2 18 A2 20 A2 30 A2 38 A2 48 A2 50 A2 60 A2 68 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.287101752714581 Found in 9 files
		$x130 = { 04 05 02 05 02 03 02 02 08 03 02 03 02 03 02 04 02 03 02 04 02 08 02 01 08 08 02 03 02 02 06 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 38 files
		$x10 = { 80 A4 90 A4 A0 A4 B0 A4 C0 A4 D0 A4 E0 A4 F0 A4 00 A5 10 A5 20 A5 30 A5 40 A5 50 A5 60 A5 70 A5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1686450333085068 Found in 10 files
		$x134 = { AB 00 AC 10 AC 18 AC 28 AC 30 AC 40 AC 48 AC 58 AC 60 AC 70 AC 78 AC 88 AC 90 AC A0 AC A8 AC B8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.147589457504889 Found in 10 files
		$x139 = { 02 02 02 02 02 02 02 02 02 02 13 03 03 03 03 03 03 03 03 03 03 03 03 23 03 03 34 04 04 04 44 F1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9025182662886326 Found in 11 files
		$x140 = { 00 69 6E 74 65 72 6E 61 6C 2F 72 65 66 6C 65 63 74 6C 69 74 65 2E 28 2A 72 74 79 70 65 29 2E 43 } //This might be a string? Looks like:internal/reflectlite.(*rtype).C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 12 files
		$x142 = { A3 B8 A3 C0 A3 D0 A3 D8 A3 E8 A3 F0 A3 00 A4 08 A4 18 A4 20 A4 30 A4 38 A4 48 A4 50 A4 60 A4 68 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 7 files
		$x144 = { AB B0 AB B8 AB E0 AB E8 AB F8 AB 00 AC 10 AC 18 AC 28 AC 30 AC 40 AC 48 AC 58 AC 60 AC 70 AC 78 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 12 files
		$x145 = { A8 70 A8 80 A8 88 A8 98 A8 A0 A8 B0 A8 B8 A8 C8 A8 D0 A8 E0 A8 E8 A8 F8 A8 00 A9 10 A9 18 A9 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9375 Found in 9 files
		$x146 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 77 AF 0C 92 74 08 02 41 E1 C1 07 E6 D6 18 E6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5931390622295662 Found in 12 files
		$x149 = { 63 61 6C 6C 2E 28 2A 50 72 6F 63 29 2E 43 61 6C 6C 00 73 79 73 63 61 6C 6C 2E 28 2A 50 72 6F 63 } //This might be a string? Looks like:call.(*Proc).Callsyscall.(*Proc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.538909765557392 Found in 14 files
		$x151 = { 54 46 31 36 50 74 72 46 72 6F 6D 53 74 72 69 6E 67 00 73 79 73 63 61 6C 6C 2E 28 2A 44 4C 4C 29 } //This might be a string? Looks like:TF16PtrFromStringsyscall.(*DLL)
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.226409765557392 Found in 9 files
		$x153 = { 2E 28 2A 46 72 61 6D 65 73 29 2E 4E 65 78 74 00 72 75 6E 74 69 6D 65 2E 65 78 70 61 6E 64 43 67 } //This might be a string? Looks like:.(*Frames).Nextruntime.expandCg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.202819531114783 Found in 13 files
		$x154 = { 6D 65 2E 67 66 70 75 72 67 65 00 72 75 6E 74 69 6D 65 2E 75 6E 6C 6F 63 6B 4F 53 54 68 72 65 61 } //This might be a string? Looks like:me.gfpurgeruntime.unlockOSThrea
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.038909765557392 Found in 9 files
		$x155 = { 2E 28 2A 72 74 79 70 65 29 2E 43 6F 6D 70 61 72 61 62 6C 65 00 69 6E 74 65 72 6E 61 6C 2F 72 65 } //This might be a string? Looks like:.(*rtype).Comparableinternal/re
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 11 files
		$x157 = { A5 98 A5 A0 A5 B0 A5 B8 A5 C8 A5 D0 A5 E0 A5 E8 A5 F8 A5 00 A6 10 A6 18 A6 28 A6 30 A6 40 A6 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x158 = { 50 AF 58 AF 60 AF 68 AF 70 AF 78 AF 80 AF 88 AF 90 AF 98 AF A0 AF A8 AF B0 AF B8 AF C0 AF C8 AF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7889097655573916 Found in 26 files
		$x30 = { 69 00 73 00 68 00 2D 00 64 00 6F 00 6D 00 69 00 6E 00 69 00 63 00 61 00 6E 00 20 00 72 00 65 00 } //This might be a string? Looks like:ish-dominican re
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 38 files
		$x2 = { 50 A8 60 A8 70 A8 80 A8 90 A8 A0 A8 B0 A8 C0 A8 D0 A8 E0 A8 F0 A8 00 A9 10 A9 20 A9 30 A9 40 A9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.015319531114783 Found in 11 files
		$x161 = { 6C 62 61 63 6B 5F 77 69 6E 64 6F 77 73 2E 73 00 69 6E 74 65 72 6E 61 6C 2F 73 79 73 63 61 6C 6C } //This might be a string? Looks like:lback_windows.sinternal/syscall
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9025182662886326 Found in 12 files
		$x162 = { 6C 65 43 6F 6D 70 6C 65 74 69 6F 6E 4E 6F 74 69 66 69 63 61 74 69 6F 6E 4D 6F 64 65 73 00 73 79 } //This might be a string? Looks like:leCompletionNotificationModessy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 15 files
		$x163 = { C0 AE C8 AE D0 AE D8 AE E0 AE E8 AE F0 AE F8 AE 00 AF 08 AF 10 AF 18 AF 20 AF 28 AF 30 AF 38 AF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 16 files
		$x164 = { A5 D8 A5 E0 A5 E8 A5 F0 A5 F8 A5 00 A6 08 A6 10 A6 18 A6 20 A6 28 A6 30 A6 38 A6 40 A6 48 A6 50 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.265319531114783 Found in 10 files
		$x165 = { 6E 61 74 65 50 72 6F 63 65 73 73 00 73 79 73 63 61 6C 6C 2E 55 6E 6D 61 70 56 69 65 77 4F 66 46 } //This might be a string? Looks like:nateProcesssyscall.UnmapViewOfF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x167 = { 30 A6 38 A6 40 A6 48 A6 50 A6 58 A6 60 A6 68 A6 70 A6 78 A6 80 A6 88 A6 90 A6 98 A6 A0 A6 A8 A6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.827819531114783 Found in 13 files
		$x168 = { 33 00 72 75 6E 74 69 6D 65 2E 63 6F 6E 63 61 74 73 74 72 69 6E 67 34 00 72 75 6E 74 69 6D 65 2E } //This might be a string? Looks like:3runtime.concatstring4runtime.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.413909765557392 Found in 11 files
		$x170 = "upInfoWProcess32FirstWUnmapViewO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 25 files
		$x173 = { A8 A5 B0 A5 B8 A5 C0 A5 C8 A5 D0 A5 D8 A5 E0 A5 E8 A5 F0 A5 F8 A5 00 A6 08 A6 10 A6 18 A6 20 A6 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.390319531114783 Found in 10 files
		$x174 = { 65 72 73 69 6F 6E 3D 27 31 2E 30 27 3E 0D 0A 20 20 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C 6E } //This might be a string? Looks like:ersion='1.0'>\r\n  <trustInfo xmln
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 36 files
		$x6 = { 70 A9 80 A9 90 A9 A0 A9 B0 A9 C0 A9 D0 A9 E0 A9 F0 A9 00 AA 10 AA 20 AA 30 AA 40 AA 50 AA 60 AA } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7264097655573916 Found in 27 files
		$x8 = { 20 69 74 65 72 61 74 6F 72 27 00 00 00 00 60 65 68 20 76 65 63 74 6F 72 20 64 65 73 74 72 75 63 } //This might be a string? Looks like: iterator'`eh vector destruc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.015319531114783 Found in 9 files
		$x177 = { 73 2E 67 6F 00 72 75 6E 74 69 6D 65 2F 6D 70 61 67 65 63 61 63 68 65 2E 67 6F 00 72 75 6E 74 69 } //This might be a string? Looks like:s.goruntime/mpagecache.gorunti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x179 = { A4 50 A4 60 A4 68 A4 78 A4 80 A4 90 A4 98 A4 A8 A4 B0 A4 C0 A4 C8 A4 D8 A4 E0 A4 F0 A4 F8 A4 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.8042292966721747 Found in 11 files
		$x180 = { 6D 65 2F 72 75 6E 74 69 6D 65 32 2E 67 6F 00 72 75 6E 74 69 6D 65 2F 70 72 6F 63 2E 67 6F 00 72 } //This might be a string? Looks like:me/runtime2.goruntime/proc.gor
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.863608500731241 Found in 11 files
		$x181 = { 63 61 6C 6C 2E 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 00 73 79 73 63 61 6C 6C 2E 43 } //This might be a string? Looks like:call.CreateFileMappingsyscall.C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 6 files
		$x182 = { F0 48 0F B1 5A 20 40 0F 94 C6 90 40 84 F6 74 D5 48 83 F9 02 75 04 31 C9 EB 16 FF 4C 24 14 EB 10 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 37 files
		$x16 = { AB 80 AB 90 AB A0 AB B0 AB C0 AB D0 AB E0 AB F0 AB 00 AC 10 AC 20 AC 30 AC 40 AC 50 AC 60 AC 70 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.179229296672175 Found in 8 files
		$x184 = { 72 6C 64 47 43 00 72 75 6E 74 69 6D 65 2E 73 74 6F 70 54 68 65 57 6F 72 6C 64 57 69 74 68 53 65 } //This might be a string? Looks like:rldGCruntime.stopTheWorldWithSe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.634669235259032 Found in 27 files
		$x18 = { 00 00 00 01 00 00 03 08 06 08 00 08 06 08 02 08 00 01 04 00 05 00 05 04 05 04 05 04 05 08 05 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.093139062229566 Found in 12 files
		$x185 = { 6C 65 61 73 65 00 73 79 6E 63 2E 72 75 6E 74 69 6D 65 5F 6E 6F 74 69 66 79 4C 69 73 74 43 68 65 } //This might be a string? Looks like:leasesync.runtime_notifyListChe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x188 = { 10 AF 18 AF 20 AF 28 AF 30 AF 38 AF 40 AF 48 AF 50 AF 58 AF 60 AF 68 AF 70 AF 78 AF 80 AF 88 AF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 9 files
		$x189 = { 60 A3 70 A3 78 A3 88 A3 90 A3 A0 A3 A8 A3 B8 A3 C0 A3 D0 A3 D8 A3 E8 A3 F0 A3 00 A4 08 A4 18 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 10 files
		$x191 = { AD D8 AD E0 AD F0 AD F8 AD 08 AE 10 AE 20 AE 28 AE 38 AE 40 AE 50 AE 58 AE 68 AE 70 AE 80 AE 88 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.375 Found in 10 files
		$x193 = { 1E 3A 0C 1F 0F 97 C0 48 8D 04 45 FF FF FF FF C3 49 83 F8 08 76 0B 48 8B 06 48 8B 0F 48 39 C8 75 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.265319531114783 Found in 11 files
		$x196 = { 65 72 73 79 73 63 61 6C 6C 62 6C 6F 63 6B 5F 68 61 6E 64 6F 66 66 00 72 75 6E 74 69 6D 65 2E 65 } //This might be a string? Looks like:ersyscallblock_handoffruntime.e
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9917292966721747 Found in 9 files
		$x197 = { 50 61 74 68 45 72 72 6F 72 00 69 6E 74 65 72 6E 61 6C 2F 73 79 73 63 61 6C 6C 2F 77 69 6E 64 6F } //This might be a string? Looks like:PathErrorinternal/syscall/windo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 37 files
		$x29 = { A1 70 A1 80 A1 90 A1 A0 A1 B0 A1 C0 A1 D0 A1 E0 A1 F0 A1 00 A2 10 A2 20 A2 30 A2 40 A2 50 A2 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 8 files
		$x198 = { A7 E8 A7 F0 A7 F8 A7 00 A8 08 A8 10 A8 18 A8 20 A8 28 A8 30 A8 38 A8 40 A8 48 A8 50 A8 58 A8 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.375 Found in 9 files
		$x200 = { 64 4D 75 74 65 78 29 2E 72 77 6C 6F 63 6B 00 69 6E 74 65 72 6E 61 6C 2F 70 6F 6C 6C 2E 28 2A 66 } //This might be a string? Looks like:dMutex).rwlockinternal/poll.(*f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.827819531114783 Found in 14 files
		$x31 = { 74 69 6D 65 2F 6D 72 61 6E 67 65 73 2E 67 6F 00 72 75 6E 74 69 6D 65 2F 6D 70 61 67 65 61 6C 6C } //This might be a string? Looks like:time/mranges.goruntime/mpageall
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.202819531114783 Found in 13 files
		$x34 = { 6C 2F 62 79 74 65 61 6C 67 2E 69 6E 69 74 2E 30 00 63 6D 70 62 6F 64 79 00 72 75 6E 74 69 6D 65 } //This might be a string? Looks like:l/bytealg.init.0cmpbodyruntime
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 36 files
		$x3 = { D0 A3 E0 A3 F0 A3 00 A4 10 A4 20 A4 30 A4 40 A4 50 A4 60 A4 70 A4 80 A4 90 A4 A0 A4 B0 A4 C0 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 6 files
		$x36 = { A0 A3 A8 A3 B8 A3 C0 A3 D0 A3 D8 A3 18 A4 20 A4 30 A4 38 A4 60 A4 68 A4 78 A4 80 A4 90 A4 98 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x37 = { 20 A1 28 A1 30 A1 38 A1 40 A1 48 A1 50 A1 58 A1 60 A1 68 A1 70 A1 78 A1 80 A1 88 A1 90 A1 98 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 10 files
		$x38 = { C0 A1 C8 A1 D0 A1 D8 A1 E0 A1 E8 A1 F0 A1 F8 A1 00 A2 08 A2 10 A2 18 A2 20 A2 28 A2 30 A2 38 A2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.116729296672175 Found in 15 files
		$x39 = { 2E 75 6E 6C 6F 63 6B 4F 53 54 68 72 65 61 64 00 72 75 6E 74 69 6D 65 2E 64 6F 75 6E 6C 6F 63 6B } //This might be a string? Looks like:.unlockOSThreadruntime.dounlock
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.140319531114783 Found in 8 files
		$x42 = { 65 61 6C 67 2F 69 6E 64 65 78 62 79 74 65 5F 61 6D 64 36 34 2E 73 00 69 6E 74 65 72 6E 61 6C 2F } //This might be a string? Looks like:ealg/indexbyte_amd64.sinternal/
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 22 files
		$x44 = { 58 AD 60 AD 68 AD 70 AD 78 AD 80 AD 88 AD 90 AD 98 AD A0 AD A8 AD B0 AD B8 AD C0 AD C8 AD D0 AD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 7 files
		$x45 = { A2 B8 A2 C8 A2 D0 A2 E0 A2 E8 A2 F8 A2 00 A3 10 A3 18 A3 28 A3 30 A3 40 A3 48 A3 58 A3 60 A3 70 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.163909765557392 Found in 9 files
		$x46 = { 46 69 6C 65 00 73 79 73 63 61 6C 6C 2E 57 53 41 45 6E 75 6D 50 72 6F 74 6F 63 6F 6C 73 00 73 79 } //This might be a string? Looks like:Filesyscall.WSAEnumProtocolssy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.3094873517384964 Found in 8 files
		$x49 = { 08 90 E9 FB FD FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2928377974034158 Found in 36 files
		$x13 = { 50 A0 60 A0 70 A0 80 A0 90 A0 A0 A0 B0 A0 C0 A0 D0 A0 E0 A0 F0 A0 00 A1 10 A1 20 A1 30 A1 40 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.494349704144249 Found in 11 files
		$x54 = { AD C0 AD C8 AD D8 AD E0 AD F0 AD F8 AD 08 AE 10 AE 20 AE 28 AE 38 AE 40 AE 50 AE 58 AE 68 AE 70 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.866729296672175 Found in 9 files
		$x55 = { 05 A2 03 05 CF 03 05 2E 02 2D 09 2E 14 A2 03 05 20 02 EF 03 09 38 02 BE 03 0A F5 03 04 3A 18 14 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.5 Found in 13 files
		$x58 = { 79 73 47 72 6F 77 2E 66 75 6E 63 32 00 72 75 6E 74 69 6D 65 2E 28 2A 70 61 67 65 41 6C 6C 6F 63 } //This might be a string? Looks like:ysGrow.func2runtime.(*pageAlloc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x60 = { A1 50 A1 58 A1 60 A1 68 A1 70 A1 78 A1 80 A1 88 A1 90 A1 98 A1 A0 A1 A8 A1 B0 A1 B8 A1 C0 A1 C8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 31 files
		$x61 = { A4 E0 A4 E8 A4 F0 A4 F8 A4 00 A5 08 A5 10 A5 18 A5 20 A5 28 A5 30 A5 38 A5 40 A5 48 A5 50 A5 58 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 18 files
		$x65 = { B0 A0 B8 A0 C0 A0 C8 A0 D0 A0 D8 A0 E0 A0 E8 A0 F0 A0 F8 A0 00 A1 08 A1 10 A1 18 A1 20 A1 28 A1 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.765319531114783 Found in 12 files
		$x67 = { 6C 65 6D 00 69 6E 74 65 72 6E 61 6C 2F 72 65 66 6C 65 63 74 6C 69 74 65 2E 74 6F 54 79 70 65 00 } //This might be a string? Looks like:leminternal/reflectlite.toType
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.5 Found in 48 files
		$x26 = { 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E } //This might be a string? Looks like:\t!L!This program cann
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.8125 Found in 10 files
		$x71 = { 73 0A 62 75 69 6C 64 09 47 4F 41 4D 44 36 34 3D 76 31 0A F9 32 43 31 86 18 20 72 00 82 42 10 41 } //This might be a string? Looks like:s\nbuild\tGOAMD64=v1\n2C1 rBA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.351409765557392 Found in 11 files
		$x72 = { 74 47 4E 6F 57 42 00 72 75 6E 74 69 6D 65 2E 67 6F 73 63 68 65 64 49 6D 70 6C 00 72 75 6E 74 69 } //This might be a string? Looks like:tGNoWBruntime.goschedImplrunti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x75 = { AA 58 AA 60 AA 68 AA 70 AA 78 AA 80 AA 88 AA 90 AA 98 AA A0 AA A8 AA B0 AA B8 AA C0 AA C8 AA D0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.801108500731241 Found in 13 files
		$x77 = { 67 6F 00 69 6E 74 65 72 6E 61 6C 2F 72 65 66 6C 65 63 74 6C 69 74 65 2F 74 79 70 65 2E 67 6F 00 } //This might be a string? Looks like:gointernal/reflectlite/type.go
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.179229296672174 Found in 34 files
		$x78 = { 72 75 73 74 49 6E 66 6F 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 63 72 } //This might be a string? Looks like:rustInfo xmlns="urn:schemas-micr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.271782221599798 Found in 9 files
		$x79 = { E8 A6 F8 A6 00 A7 10 A7 18 A7 28 A7 30 A7 40 A7 48 A7 58 A7 60 A7 70 A7 78 A7 88 A7 90 A7 A0 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.8125 Found in 7 files
		$x80 = { 81 E0 F8 FF 7F 00 49 89 D9 48 C1 EB 0D 4A 8B 34 06 45 31 C0 EB 11 41 84 00 4B 89 3C D0 4C 8D 56 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.054229296672174 Found in 7 files
		$x81 = { 74 69 6D 65 2E 70 69 43 6F 6E 74 72 6F 6C 6C 65 72 01 15 43 6F 6D 70 61 72 65 41 6E 64 53 77 61 } //This might be a string? Looks like:time.piControllerCompareAndSwa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.3125 Found in 14 files
		$x83 = { 72 6E 61 6C 2F 62 79 74 65 61 6C 67 2F 63 6F 6D 70 61 72 65 5F 61 6D 64 36 34 2E 73 00 69 6E 74 } //This might be a string? Looks like:rnal/bytealg/compare_amd64.sint
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.163909765557392 Found in 8 files
		$x84 = { 4D 89 DC 4C 0F 47 DB 4D 89 E5 4D 29 DC 49 89 C0 4C 89 E8 F0 4D 0F B1 A0 90 01 01 00 41 0F 94 C4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 33 files
		$x11 = { AC 40 AC 50 AC 60 AC 70 AC 80 AC 90 AC A0 AC B0 AC C0 AC D0 AC E0 AC F0 AC 00 AD 10 AD 20 AD 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.849601752714581 Found in 11 files
		$x85 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 21 22 23 24 25 25 26 26 27 27 28 28 28 29 29 29 2A } //This might be a string? Looks like: !"#$%%&&''((()))*
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 14 files
		$x86 = { A2 10 A2 18 A2 20 A2 28 A2 30 A2 38 A2 40 A2 48 A2 50 A2 58 A2 60 A2 68 A2 70 A2 78 A2 80 A2 88 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.093139062229566 Found in 5 files
		$x89 = { 24 68 48 89 0C 24 48 89 C3 31 C9 48 89 CF 31 F6 41 B8 04 00 00 00 45 31 C9 4D 89 CA 4C 8D 9C 24 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.054229296672174 Found in 9 files
		$x92 = { 6F 6C 6C 65 72 53 74 61 74 65 29 2E 69 6E 69 74 00 72 75 6E 74 69 6D 65 2E 28 2A 67 63 43 6F 6E } //This might be a string? Looks like:ollerState).initruntime.(*gcCon
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 31 files
		$x19 = { D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.030639062229566 Found in 8 files
		$x96 = { 69 63 61 74 69 6F 6E 4D 6F 64 65 73 00 73 79 73 63 61 6C 6C 2E 54 65 72 6D 69 6E 61 74 65 50 72 } //This might be a string? Looks like:icationModessyscall.TerminatePr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.3719873517384964 Found in 6 files
		$x98 = { CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 49 3B 66 10 0F 86 48 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.327819531114783 Found in 12 files
		$x99 = { 69 6E 64 52 75 6E 6E 61 62 6C 65 47 43 57 6F 72 6B 65 72 00 72 75 6E 74 69 6D 65 2E 28 2A 67 63 } //This might be a string? Looks like:indRunnableGCWorkerruntime.(*gc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 17 files
		$x101 = { A2 B0 A2 B8 A2 C0 A2 C8 A2 D0 A2 D8 A2 E0 A2 E8 A2 F0 A2 F8 A2 00 A3 08 A3 10 A3 18 A3 20 A3 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 11 files
		$x102 = { A2 D8 A2 E0 A2 F0 A2 F8 A2 08 A3 10 A3 20 A3 28 A3 38 A3 40 A3 50 A3 58 A3 68 A3 70 A3 80 A3 88 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.601409765557392 Found in 8 files
		$x104 = { 2D 74 72 69 6D 70 61 74 68 3D 74 72 75 65 0A 62 75 69 6C 64 09 43 47 4F 5F 45 4E 41 42 4C 45 44 } //This might be a string? Looks like:-trimpath=true\nbuild\tCGO_ENABLED
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.304229296672175 Found in 11 files
		$x105 = { 64 6F 77 73 2E 55 54 46 31 36 50 74 72 54 6F 53 74 72 69 6E 67 00 69 6E 74 65 72 6E 61 6C 2F 73 } //This might be a string? Looks like:dows.UTF16PtrToStringinternal/s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 38 files
		$x23 = { C0 AA D0 AA E0 AA F0 AA 00 AB 10 AB 20 AB 30 AB 40 AB 50 AB 60 AB 70 AB 80 AB 90 AB A0 AB B0 AB } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.116729296672174 Found in 6 files
		$x106 = { 2F 74 72 75 73 74 49 6E 66 6F 3E 0D 0A 3C 2F 61 73 73 65 6D 62 6C 79 3E 0D 0A 0D 0A 00 00 00 00 } //This might be a string? Looks like:/trustInfo>\r\n</assembly>\r\n\r\n
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.128928031846025 Found in 13 files
		$x107 = { 60 86 48 01 65 03 04 02 01 05 00 30 5C 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 4E 30 4C 30 17 06 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.051108500731241 Found in 5 files
		$x109 = { 2A 69 6E 74 65 72 66 61 63 65 20 7B 20 55 6E 77 72 61 70 28 29 20 65 72 72 6F 72 20 7D 00 1E 2A } //This might be a string? Looks like:*interface { Unwrap() error }*
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 38 files
		$x25 = { AC D0 AC E0 AC F0 AC 00 AD 10 AD 20 AD 30 AD 40 AD 50 AD 60 AD 70 AD 80 AD 90 AD A0 AD B0 AD C0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x110 = { A1 08 A1 18 A1 20 A1 30 A1 38 A1 48 A1 50 A1 60 A1 68 A1 78 A1 80 A1 90 A1 98 A1 A8 A1 B0 A1 C0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 34 files
		$x1 = { AB C0 AB D0 AB E0 AB F0 AB 00 AC 10 AC 20 AC 30 AC 40 AC 50 AC 60 AC 70 AC 80 AC 90 AC A0 AC B0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.271782221599798 Found in 28 files
		$x115 = { A5 98 A5 A0 A5 A8 A5 B0 A5 B8 A5 C0 A5 C8 A5 D0 A5 D8 A5 E0 A5 E8 A5 F0 A5 F8 A5 00 A6 08 A6 10 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.218139062229566 Found in 6 files
		$x116 = { 63 72 65 66 00 69 6E 74 65 72 6E 61 6C 2F 70 6F 6C 6C 2E 28 2A 46 44 29 2E 77 72 69 74 65 55 6E } //This might be a string? Looks like:crefinternal/poll.(*FD).writeUn
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.369349704144249 Found in 6 files
		$x117 = { 18 A2 58 A2 60 A2 70 A2 78 A2 B8 A2 C0 A2 D0 A2 D8 A2 18 A3 20 A3 30 A3 38 A3 78 A3 80 A3 90 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.292837797403416 Found in 8 files
		$x118 = { 80 A8 90 A8 98 A8 A8 A8 B0 A8 C0 A8 C8 A8 D8 A8 E0 A8 F0 A8 F8 A8 08 A9 10 A9 20 A9 28 A9 38 A9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.038909765557392 Found in 10 files
		$x123 = { 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 00 73 79 73 63 61 6C 6C 2E 43 72 65 61 74 65 50 72 6F } //This might be a string? Looks like:ateFileMappingsyscall.CreatePro
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.688307235905091 Found in 12 files
		$x124 = " not enabledno goroutines (main " ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.413909765557392 Found in 5 files
		$x125 = { 4C 61 7A 79 50 72 6F 63 00 11 2A 5B 30 5D 2A 62 69 73 65 63 74 2E 64 65 64 75 70 00 11 2A 5B 5D } //This might be a string? Looks like:LazyProc*[0]*bisect.dedup*[]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.241729296672174 Found in 10 files
		$x127 = { 73 63 61 6C 6C 2F 77 69 6E 64 6F 77 73 2E 57 53 41 4D 73 67 00 69 6E 74 65 72 6E 61 6C 2F 70 6F } //This might be a string? Looks like:scall/windows.WSAMsginternal/po
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 28 files
		$x7 = { 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 } //This might be a string? Looks like:UVWXYZ[\]^_`abcdefghijklmnopqrst
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x129 = { AD 20 AD 30 AD 38 AD 48 AD 50 AD 60 AD 68 AD 78 AD 80 AD 90 AD 98 AD A8 AD B0 AD C0 AD C8 AD D8 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 11 files
		$x131 = { A6 80 A6 88 A6 98 A6 A0 A6 B0 A6 B8 A6 C8 A6 D0 A6 E0 A6 E8 A6 F8 A6 00 A7 10 A7 18 A7 28 A7 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9292292966721747 Found in 10 files
		$x132 = { 31 00 72 75 6E 74 69 6D 65 2E 67 66 70 75 72 67 65 00 72 75 6E 74 69 6D 65 2E 75 6E 6C 6F 63 6B } //This might be a string? Looks like:1runtime.gfpurgeruntime.unlock
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.271782221599798 Found in 10 files
		$x133 = { A5 68 A5 70 A5 80 A5 88 A5 98 A5 A0 A5 B0 A5 B8 A5 C8 A5 D0 A5 E0 A5 E8 A5 F8 A5 00 A6 10 A6 18 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.476409765557392 Found in 15 files
		$x135 = { 64 44 4C 4C 00 73 79 73 63 61 6C 6C 2E 55 54 46 31 36 50 74 72 46 72 6F 6D 53 74 72 69 6E 67 00 } //This might be a string? Looks like:dDLLsyscall.UTF16PtrFromString
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 35 files
		$x12 = { 30 A3 40 A3 50 A3 60 A3 70 A3 80 A3 90 A3 A0 A3 B0 A3 C0 A3 D0 A3 E0 A3 F0 A3 00 A4 10 A4 20 A4 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 22 files
		$x136 = { D8 A2 E0 A2 E8 A2 F0 A2 F8 A2 00 A3 08 A3 10 A3 18 A3 20 A3 28 A3 30 A3 38 A3 40 A3 48 A3 50 A3 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.371696364505181 Found in 7 files
		$x137 = { AB F8 AB 00 AC 10 AC 18 AC 58 AC 60 AC 70 AC 78 AC A0 AC A8 AC B8 AC C0 AC D0 AC D8 AC 18 AD 20 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 37 files
		$x14 = { A4 10 A4 20 A4 30 A4 40 A4 50 A4 60 A4 70 A4 80 A4 90 A4 A0 A4 B0 A4 C0 A4 D0 A4 E0 A4 F0 A4 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.202819531114783 Found in 17 files
		$x138 = { 20 20 3C 74 72 75 73 74 49 6E 66 6F 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D } //This might be a string? Looks like:  <trustInfo xmlns="urn:schemas-
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x141 = { AF 20 AF 30 AF 38 AF 60 AF 68 AF 78 AF 80 AF 90 AF 98 AF A8 AF B0 AF C0 AF C8 AF D8 AF E0 AF F0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7806390622295662 Found in 13 files
		$x143 = { 67 6F 00 72 75 6E 74 69 6D 65 2F 6D 63 65 6E 74 72 61 6C 2E 67 6F 00 72 75 6E 74 69 6D 65 2F 6D } //This might be a string? Looks like:goruntime/mcentral.goruntime/m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 9 files
		$x147 = { 72 75 6E 74 69 6D 65 2E 6D 61 70 61 63 63 65 73 73 32 00 72 75 6E 74 69 6D 65 2E 6D 61 70 61 73 } //This might be a string? Looks like:runtime.mapaccess2runtime.mapas
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.902518266288633 Found in 6 files
		$x148 = { 39 00 00 84 C0 0F 85 F8 00 00 00 48 8B 44 24 78 48 8B 7C 24 38 4C 8B 44 24 28 0F B6 4C 24 16 48 } //This might be a string? Looks like:9HD$xH|$8LD$(L$H
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.3481061300625727 Found in 8 files
		$x150 = { AB D0 AB D8 AB 00 AC 08 AC 18 AC 20 AC 30 AC 38 AC 48 AC 50 AC 60 AC 68 AC 78 AC 80 AC 90 AC 98 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 10 files
		$x152 = { D0 AD D8 AD E8 AD F0 AD 00 AE 08 AE 18 AE 20 AE 30 AE 38 AE 48 AE 50 AE 60 AE 68 AE 78 AE 80 AE } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x156 = { A2 28 A2 30 A2 38 A2 40 A2 48 A2 50 A2 58 A2 60 A2 68 A2 70 A2 78 A2 80 A2 88 A2 90 A2 98 A2 A0 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.851409765557392 Found in 26 files
		$x27 = { E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 00 00 20 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4772170014624826 Found in 12 files
		$x159 = { AE B8 AE C0 AE C8 AE D0 AE D8 AE E0 AE E8 AE F0 AE F8 AE 00 AF 08 AF 10 AF 18 AF 20 AF 28 AF 30 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.484265829249441 Found in 15 files
		$x160 = { 08 05 02 05 02 03 02 03 02 01 06 04 02 02 04 08 02 03 04 04 02 02 06 03 02 02 06 05 02 03 08 04 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 15 files
		$x166 = { 76 69 6C 65 67 65 73 3E 0D 0A 20 20 20 20 20 20 20 20 3C 72 65 71 75 65 73 74 65 64 45 78 65 63 } //This might be a string? Looks like:vileges>\r\n        <requestedExec
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.155639062229566 Found in 12 files
		$x169 = { 69 6D 65 2F 7A 63 61 6C 6C 62 61 63 6B 5F 77 69 6E 64 6F 77 73 2E 73 00 69 6E 74 65 72 6E 61 6C } //This might be a string? Looks like:ime/zcallback_windows.sinternal
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.288909765557392 Found in 9 files
		$x171 = { 61 70 5B 72 75 6E 74 69 6D 65 2E 5F 74 79 70 65 50 61 69 72 5D 73 74 72 75 63 74 20 7B 7D 00 21 } //This might be a string? Looks like:ap[runtime._typePair]struct {}!
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.8584585933443494 Found in 28 files
		$x5 = { 00 00 00 60 64 65 66 61 75 6C 74 20 63 6F 6E 73 74 72 75 63 74 6F 72 20 63 6C 6F 73 75 72 65 27 } //This might be a string? Looks like:`default constructor closure'
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.265319531114783 Found in 15 files
		$x172 = { 63 31 00 72 75 6E 74 69 6D 65 2E 62 6C 6F 63 6B 41 6C 69 67 6E 53 75 6D 6D 61 72 79 52 61 6E 67 } //This might be a string? Looks like:c1runtime.blockAlignSummaryRang
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9681390622295662 Found in 7 files
		$x175 = { 64 6F 77 73 2E 67 6F 00 69 6E 74 65 72 6E 61 6C 2F 70 6F 6C 6C 2F 66 64 5F 77 69 6E 64 6F 77 73 } //This might be a string? Looks like:dows.gointernal/poll/fd_windows
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x176 = { 20 A5 28 A5 38 A5 40 A5 50 A5 58 A5 68 A5 70 A5 80 A5 88 A5 98 A5 A0 A5 B0 A5 B8 A5 C8 A5 D0 A5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.448019116267279 Found in 8 files
		$x178 = { A2 88 A2 98 A2 A0 A2 B0 A2 B8 A2 C8 A2 D0 A2 E0 A2 E8 A2 F8 A2 00 A3 10 A3 18 A3 28 A3 30 A3 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1686450333085068 Found in 8 files
		$x183 = { F8 A6 20 A7 28 A7 38 A7 40 A7 50 A7 58 A7 68 A7 70 A7 80 A7 88 A7 98 A7 A0 A7 B0 A7 B8 A7 C8 A7 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.1761085007312415 Found in 15 files
		$x186 = { 08 48 83 C6 10 48 83 C7 10 48 0F BC D8 48 31 C0 8A 0C 1E 3A 0C 1F 0F 97 C0 48 8D 04 45 FF FF FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.1183927290103626 Found in 11 files
		$x187 = { 90 E9 FB FD FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.051108500731241 Found in 14 files
		$x190 = "ng with NUL passed to StringToUT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.6792292966721747 Found in 9 files
		$x192 = { 63 00 72 75 6E 74 69 6D 65 2E 67 63 69 6E 69 74 00 72 75 6E 74 69 6D 65 2E 67 63 65 6E 61 62 6C } //This might be a string? Looks like:cruntime.gcinitruntime.gcenabl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.890319531114783 Found in 28 files
		$x22 = "PolicyGetProcessTerminationMetho" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.030639062229566 Found in 11 files
		$x194 = { 63 6F 64 65 2F 75 74 66 31 36 2F 75 74 66 31 36 2E 67 6F 00 69 6E 74 65 72 6E 61 6C 2F 72 65 66 } //This might be a string? Looks like:code/utf16/utf16.gointernal/ref
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.4056390622295662 Found in 12 files
		$x195 = { A1 D8 A1 E8 A1 F0 A1 00 A2 08 A2 18 A2 20 A2 30 A2 38 A2 48 A2 50 A2 60 A2 68 A2 78 A2 80 A2 90 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 32 files
		$x28 = "56789:;<=>?@ABCDEFGHIJKLMNOPQRST" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1686450333085068 Found in 11 files
		$x199 = { F8 AC 08 AD 10 AD 20 AD 28 AD 38 AD 40 AD 50 AD 58 AD 68 AD 70 AD 80 AD 88 AD 98 AD A0 AD B0 AD } 

		condition:
(19 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30) ) or (163 of ($x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x13,$x51,$x52,$x17,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x24,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83,$x84,$x85,$x86,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x20,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x23,$x106,$x107,$x108,$x109,$x25,$x110,$x111,$x0,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x10,$x133,$x134,$x135,$x136,$x137,$x14,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x2,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x29,$x198,$x199,$x200) )}