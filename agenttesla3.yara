rule malware_samples_agenttesla
{
	//Input TP Rate:
	//44/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 32 files
		$x0 = { 00 74 00 65 00 63 00 74 } //This might be a string? Looks like:tect
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x1 = { 74 00 77 00 6F 00 72 00 } //This might be a string? Looks like:twor
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x290 = { 64 65 72 08 31 37 2E 30 } //This might be a string? Looks like:der17.0
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 45 files
		$x2 = "FileVers" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 34 files
		$x291 = { 00 6F 00 6D 00 70 00 61 } //This might be a string? Looks like:ompa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x3 = { 00 54 00 6F 00 6B 00 65 } //This might be a string? Looks like:Toke
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4056390622295665 Found in 28 files
		$x4 = { 00 72 00 72 00 6F 00 72 } //This might be a string? Looks like:rror
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x5 = { 76 00 65 00 6E 00 74 00 } //This might be a string? Looks like:vent
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x292 = "get_Coun" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 34 files
		$x293 = { 00 47 65 74 4F 62 6A 65 } //This might be a string? Looks like:GetObje
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 13 files
		$x6 = "requency" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 30 files
		$x294 = { 00 67 65 74 5F 57 69 64 } //This might be a string? Looks like:get_Wid
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 14 files
		$x7 = { 62 00 65 00 65 00 6E 00 } //This might be a string? Looks like:been
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x8 = "Terminat" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x9 = { 00 61 00 74 00 65 00 54 } //This might be a string? Looks like:ateT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 18 files
		$x10 = "Uninitia" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x11 = { 00 6C 00 69 00 63 00 61 } //This might be a string? Looks like:lica
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 23 files
		$x295 = { 00 00 00 EF BB BF 3C 3F } //This might be a string? Looks like:<?
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x12 = { 61 00 62 00 6C 00 65 00 } //This might be a string? Looks like:able
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x296 = "esourceC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 23 files
		$x13 = { 00 74 00 65 00 72 00 20 } //This might be a string? Looks like:ter 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 13 files
		$x14 = { 65 00 52 00 65 00 73 00 } //This might be a string? Looks like:eRes
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x15 = "Register" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x16 = { 72 00 61 00 6E 00 67 00 } //This might be a string? Looks like:rang
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x17 = { 63 00 6F 00 6E 00 73 00 } //This might be a string? Looks like:cons
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 36 files
		$x297 = "escripti" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 32 files
		$x298 = { 65 74 50 69 78 65 6C 00 } //This might be a string? Looks like:etPixel
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 31 files
		$x299 = { 6D 70 6F 6E 65 6E 74 00 } //This might be a string? Looks like:mponent
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x18 = { 77 00 6F 00 72 00 64 00 } //This might be a string? Looks like:word
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x19 = { 65 00 78 00 74 00 20 00 } //This might be a string? Looks like:ext 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x20 = { 00 43 00 44 00 45 00 46 } //This might be a string? Looks like:CDEF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x21 = { 61 00 74 00 6F 00 72 00 } //This might be a string? Looks like:ator
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 19 files
		$x22 = { 00 65 00 72 00 65 00 6E } //This might be a string? Looks like:eren
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 24 files
		$x23 = { 65 00 61 00 74 00 65 00 } //This might be a string? Looks like:eate
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 31 files
		$x300 = { 45 78 65 4D 61 69 6E 00 } //This might be a string? Looks like:ExeMain
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 46 files
		$x301 = { BD 04 EF FE 00 00 01 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x24 = { 00 74 00 68 00 65 00 20 } //This might be a string? Looks like:the 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x25 = { 00 76 00 61 00 6C 00 75 } //This might be a string? Looks like:valu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x26 = { 00 68 00 65 00 20 00 73 } //This might be a string? Looks like:he s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x27 = { 6F 00 70 00 65 00 6E 00 } //This might be a string? Looks like:open
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x28 = { 00 6C 00 61 00 6E 00 63 } //This might be a string? Looks like:lanc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 27 files
		$x29 = { 45 00 72 00 72 00 6F 00 } //This might be a string? Looks like:Erro
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x30 = { 51 00 75 00 6F 00 74 00 } //This might be a string? Looks like:Quot
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x302 = "orlib, V" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 38 files
		$x31 = "tializeC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x32 = { 00 73 00 74 00 61 00 6E } //This might be a string? Looks like:stan
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x33 = { 65 00 20 00 69 00 6E 00 } //This might be a string? Looks like:e in
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x34 = { 6E 00 20 00 6C 00 65 00 } //This might be a string? Looks like:n le
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x35 = { 00 6F 00 6B 00 65 00 6E } //This might be a string? Looks like:oken
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x36 = { 65 00 20 00 69 00 73 00 } //This might be a string? Looks like:e is
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 17 files
		$x37 = { 63 00 6F 00 6D 00 6D 00 } //This might be a string? Looks like:comm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x38 = { 00 53 00 54 00 45 00 4D } //This might be a string? Looks like:STEM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 49 files
		$x39 = "Version=" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 19 files
		$x40 = "vailable" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 43 files
		$x41 = { 6F 00 6D 00 6D 00 65 00 } //This might be a string? Looks like:omme
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x42 = { 72 00 61 00 74 00 6F 00 } //This might be a string? Looks like:rato
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 30 files
		$x309 = { 00 43 75 6C 74 75 72 65 } //This might be a string? Looks like:Culture
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x43 = "peration" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 12 files
		$x44 = { 00 76 00 61 00 72 00 69 } //This might be a string? Looks like:vari
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 29 files
		$x45 = { 72 00 6F 00 67 00 72 00 } //This might be a string? Looks like:rogr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 46 files
		$x46 = "ublicKey" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 26 files
		$x310 = { 30 22 20 65 6E 63 6F 64 } //This might be a string? Looks like:0" encod
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x47 = "ditional" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 26 files
		$x312 = { 54 00 72 00 61 00 64 00 } //This might be a string? Looks like:Trad
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 13 files
		$x48 = "ferences" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x49 = { 00 69 00 73 00 20 00 70 } //This might be a string? Looks like:is p
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x313 = "aximizeB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x315 = { 00 00 00 E0 00 02 01 0B } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x50 = { 68 00 69 00 6E 00 67 00 } //This might be a string? Looks like:hing
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 18 files
		$x51 = "rrentPro" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x52 = "CreateFi" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x53 = { 00 20 00 72 00 75 00 6E } //This might be a string? Looks like: run
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x54 = "initiali" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 38 files
		$x55 = "lyIdenti" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x56 = { 00 73 00 69 00 6E 00 67 } //This might be a string? Looks like:sing
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x57 = { 00 6F 00 63 00 61 00 6C } //This might be a string? Looks like:ocal
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4056390622295665 Found in 40 files
		$x58 = { 00 00 FF FF FF FF 01 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x59 = { 55 00 73 00 65 00 72 00 } //This might be a string? Looks like:User
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 26 files
		$x60 = { 6F 00 63 00 61 00 74 00 } //This might be a string? Looks like:ocat
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x322 = "ystem.Li" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x61 = { 00 20 00 70 00 61 00 73 } //This might be a string? Looks like: pas
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 29 files
		$x323 = { 00 49 45 4E 44 AE 42 60 } //This might be a string? Looks like:IENDB`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x62 = { 20 00 75 00 73 00 65 00 } //This might be a string? Looks like: use
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x63 = { 00 20 00 70 00 61 00 72 } //This might be a string? Looks like: par
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x324 = "finedTyp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 31 files
		$x326 = "t_FormBo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x64 = { 00 6C 00 65 00 20 00 63 } //This might be a string? Looks like:le c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 17 files
		$x327 = { 65 74 5F 47 00 67 65 74 } //This might be a string? Looks like:et_Gget
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 34 files
		$x328 = { 6E 00 53 79 73 74 65 6D } //This might be a string? Looks like:nSystem
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 18 files
		$x65 = { 74 00 65 00 78 00 74 00 } //This might be a string? Looks like:text
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x66 = "VAPI32.d" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x67 = { 00 72 00 6F 00 6C 00 20 } //This might be a string? Looks like:rol 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x68 = { 20 00 6D 00 61 00 6E 00 } //This might be a string? Looks like: man
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x69 = { 00 2E 3F 41 56 65 78 63 } //This might be a string? Looks like:.?AVexc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x70 = { 00 77 00 61 00 69 00 74 } //This might be a string? Looks like:wait
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 30 files
		$x329 = "set_Fore" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x71 = { 63 00 6F 00 72 00 65 00 } //This might be a string? Looks like:core
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x72 = { 00 20 00 69 00 6E 00 73 } //This might be a string? Looks like: ins
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 26 files
		$x330 = "gableAtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x73 = { 4C 00 6F 00 63 00 6B 00 } //This might be a string? Looks like:Lock
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 26 files
		$x332 = { 00 72 00 74 00 69 00 65 } //This might be a string? Looks like:rtie
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x74 = { 00 67 00 65 00 74 00 5F } //This might be a string? Looks like:get_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x335 = "lyProduc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 12 files
		$x75 = { 00 61 00 73 00 20 00 63 } //This might be a string? Looks like:as c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 20 files
		$x76 = { 65 00 6D 00 65 00 6E 00 } //This might be a string? Looks like:emen
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x77 = { 62 00 6C 00 65 00 20 00 } //This might be a string? Looks like:ble 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x336 = { 73 70 6F 73 69 6E 67 00 } //This might be a string? Looks like:sposing
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 26 files
		$x337 = "Maximize" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 44 files
		$x78 = { 2E 64 6C 6C 00 00 00 00 } //This might be a string? Looks like:.dll
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 44 files
		$x79 = { 00 6D 00 65 00 6E 00 74 } //This might be a string? Looks like:ment
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 18 files
		$x80 = { 75 00 70 00 70 00 6F 00 } //This might be a string? Looks like:uppo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x81 = { 00 54 00 69 00 6D 00 65 } //This might be a string? Looks like:Time
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 21 files
		$x338 = { FA 01 33 00 16 00 00 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 29 files
		$x340 = "et_Start" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 12 files
		$x82 = { 52 00 45 00 47 00 45 00 } //This might be a string? Looks like:REGE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x83 = { 00 20 00 63 00 61 00 6E } //This might be a string? Looks like: can
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x84 = "Director" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x341 = "zeCompon" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x85 = { 00 67 00 75 00 6C 00 61 } //This might be a string? Looks like:gula
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x86 = "CurrentD" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x87 = { 74 00 43 00 6F 00 64 00 } //This might be a string? Looks like:tCod
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x88 = { 18 2D 44 54 FB 21 09 40 } //This might be a string? Looks like:-DT!\t@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 42 files
		$x89 = { 40 2E 72 65 6C 6F 63 00 } //This might be a string? Looks like:@.reloc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x90 = { 69 00 6E 00 61 00 72 00 } //This might be a string? Looks like:inar
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 19 files
		$x91 = { 00 69 00 6C 00 6C 00 20 } //This might be a string? Looks like:ill 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 34 files
		$x342 = "TypeHand" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x92 = { 74 00 6F 00 20 00 70 00 } //This might be a string? Looks like:to p
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 21 files
		$x93 = { 00 69 00 6E 00 69 00 74 } //This might be a string? Looks like:init
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x343 = "semblyCo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x344 = { 0A 03 FE 04 16 FE 01 13 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 29 files
		$x94 = { 49 00 6E 00 73 00 74 00 } //This might be a string? Looks like:Inst
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x95 = "eExcepti" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x345 = { 6C 00 54 00 72 00 61 00 } //This might be a string? Looks like:lTra
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 29 files
		$x96 = "Security" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 35 files
		$x346 = { 43 00 6F 00 6D 00 70 00 } //This might be a string? Looks like:Comp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 12 files
		$x97 = { 00 65 00 20 00 67 00 69 } //This might be a string? Looks like:e gi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x98 = { 65 00 64 00 20 00 66 00 } //This might be a string? Looks like:ed f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x99 = { 00 6D 00 69 00 6E 00 61 } //This might be a string? Looks like:mina
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x100 = { 73 00 65 00 72 00 20 00 } //This might be a string? Looks like:ser 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 47 files
		$x101 = "eAttribu" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x348 = { 73 69 74 69 6F 6E 00 46 } //This might be a string? Looks like:sitionF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 22 files
		$x102 = "GetValue" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x103 = { 72 00 20 00 61 00 6E 00 } //This might be a string? Looks like:r an
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x104 = { 00 73 00 20 00 74 00 6F } //This might be a string? Looks like:s to
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 36 files
		$x350 = "ializeCo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 14 files
		$x105 = "nControl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x106 = { 72 00 65 00 6E 00 74 00 } //This might be a string? Looks like:rent
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x107 = { 6D 56 61 6C 75 65 57 00 } //This might be a string? Looks like:mValueW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x108 = { 00 74 00 69 00 6D 00 65 } //This might be a string? Looks like:time
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x109 = { 69 00 62 00 6C 00 65 00 } //This might be a string? Looks like:ible
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 36 files
		$x352 = { 00 6E 00 61 00 6C 00 4E } //This might be a string? Looks like:nalN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x110 = { 68 00 65 00 20 00 63 00 } //This might be a string? Looks like:he c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 16 files
		$x111 = { 6E 00 20 00 61 00 20 00 } //This might be a string? Looks like:n a 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 46 files
		$x354 = { 00 00 20 00 00 60 2E 72 } //This might be a string? Looks like: `.r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x112 = { 00 75 00 63 00 74 00 20 } //This might be a string? Looks like:uct 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 25 files
		$x355 = { 69 67 68 74 20 C2 A9 20 } //This might be a string? Looks like:ight  
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x113 = { 65 00 72 00 20 00 6F 00 } //This might be a string? Looks like:er o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x114 = { 73 00 20 00 74 00 68 00 } //This might be a string? Looks like:s th
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 19 files
		$x115 = "ompareSt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 36 files
		$x116 = { 72 69 74 79 3E 0D 0A 20 } //This might be a string? Looks like:rity>\r\n 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x117 = { 00 6F 00 70 00 65 00 6E } //This might be a string? Looks like:open
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 28 files
		$x358 = "ingDefau" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x118 = "VersionE" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x119 = { 00 65 00 73 00 74 00 6F } //This might be a string? Looks like:esto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 24 files
		$x120 = { 41 64 64 72 65 73 73 00 } //This might be a string? Looks like:Address
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x121 = { 70 00 74 00 73 00 20 00 } //This might be a string? Looks like:pts 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 31 files
		$x361 = "ources.r" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 33 files
		$x363 = { 00 70 00 61 00 6E 00 79 } //This might be a string? Looks like:pany
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x122 = { 69 00 6E 00 75 00 65 00 } //This might be a string? Looks like:inue
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x123 = "ystemDir" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x124 = "eSecurit" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x125 = { 73 74 61 6E 63 65 00 00 } //This might be a string? Looks like:stance
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 19 files
		$x126 = { 00 6E 00 69 00 74 00 69 } //This might be a string? Looks like:niti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x127 = { 00 72 00 65 00 6E 00 63 } //This might be a string? Looks like:renc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 23 files
		$x128 = { 00 6F 00 6E 00 74 00 61 } //This might be a string? Looks like:onta
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x129 = { 00 61 00 20 00 63 00 6F } //This might be a string? Looks like:a co
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x130 = { 65 00 72 00 20 00 69 00 } //This might be a string? Looks like:er i
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 20 files
		$x131 = "rocessor" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x132 = { 76 00 61 00 6C 00 69 00 } //This might be a string? Looks like:vali
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 17 files
		$x133 = "Critical" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 31 files
		$x367 = { 00 67 65 74 5F 43 6F 75 } //This might be a string? Looks like:get_Cou
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x134 = { 00 6C 00 74 00 69 00 70 } //This might be a string? Looks like:ltip
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 33 files
		$x369 = { 43 75 6C 74 75 72 65 00 } //This might be a string? Looks like:Culture
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 23 files
		$x135 = { 00 70 00 6C 00 61 00 79 } //This might be a string? Looks like:play
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 29 files
		$x371 = { 6D 00 61 00 72 00 6B 00 } //This might be a string? Looks like:mark
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x136 = { 74 00 20 00 69 00 6E 00 } //This might be a string? Looks like:t in
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 15 files
		$x137 = "romStrin" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 12 files
		$x138 = { 70 00 61 00 67 00 65 00 } //This might be a string? Looks like:page
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 24 files
		$x377 = { 3A 61 73 6D 2E 76 32 22 } //This might be a string? Looks like::asm.v2"
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 24 files
		$x139 = "eDirecto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x140 = { 00 6C 00 20 00 50 00 61 } //This might be a string? Looks like:l Pa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x141 = { 00 6F 00 74 00 20 00 62 } //This might be a string? Looks like:ot b
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x142 = { 69 00 6F 00 6E 00 20 00 } //This might be a string? Looks like:ion 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x143 = { 00 43 00 6F 00 6D 00 62 } //This might be a string? Looks like:Comb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 34 files
		$x288 = "InteropS" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 31 files
		$x289 = { 01 00 1A 2E 4E 45 54 46 } //This might be a string? Looks like:.NETF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x144 = { 00 69 00 6C 00 74 00 65 } //This might be a string? Looks like:ilte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 22 files
		$x145 = "etString" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 18 files
		$x146 = "ocessorA" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 17 files
		$x147 = { 00 6D 00 3A 00 73 00 73 } //This might be a string? Looks like:m:ss
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x148 = { 00 6F 00 62 00 65 00 72 } //This might be a string? Looks like:ober
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 14 files
		$x149 = "s versio" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 18 files
		$x150 = "23456789" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x151 = { 73 00 69 00 62 00 6C 00 } //This might be a string? Looks like:sibl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x152 = { 54 00 49 00 4F 00 4E 00 } //This might be a string? Looks like:TION
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 18 files
		$x153 = { 00 63 00 6F 00 72 00 72 } //This might be a string? Looks like:corr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 40 files
		$x154 = "equested" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x155 = "mputerNa" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x156 = { 00 72 00 6D 00 61 00 74 } //This might be a string? Looks like:rmat
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 45 files
		$x157 = "Exceptio" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 44 files
		$x158 = "Debugger" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 13 files
		$x159 = { 00 20 00 61 00 70 00 70 } //This might be a string? Looks like: app
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x160 = { 00 69 00 6E 00 61 00 74 } //This might be a string? Looks like:inat
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 16 files
		$x161 = { 00 6B 65 72 6E 65 6C 33 } //This might be a string? Looks like:kernel3
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x162 = "formance" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x163 = "ntProces" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x164 = { 6E 00 64 00 6C 00 65 00 } //This might be a string? Looks like:ndle
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x165 = { 73 00 20 00 64 00 65 00 } //This might be a string? Looks like:s de
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x166 = { 69 00 6E 00 20 00 66 00 } //This might be a string? Looks like:in f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x167 = { 00 6F 00 6D 00 65 00 20 } //This might be a string? Looks like:ome 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 38 files
		$x168 = { 00 70 00 65 00 72 00 74 } //This might be a string? Looks like:pert
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x169 = { 00 65 00 20 00 73 00 63 } //This might be a string? Looks like:e sc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x170 = { 61 00 63 00 74 00 69 00 } //This might be a string? Looks like:acti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 30 files
		$x171 = { 45 6E 61 62 6C 65 64 00 } //This might be a string? Looks like:Enabled
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x172 = { 61 00 69 00 6E 00 65 00 } //This might be a string? Looks like:aine
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x173 = { 6F 00 73 00 65 00 20 00 } //This might be a string? Looks like:ose 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x174 = { 00 71 00 75 00 65 00 73 } //This might be a string? Looks like:ques
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x175 = { 75 00 73 00 65 00 20 00 } //This might be a string? Looks like:use 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5 Found in 15 files
		$x176 = { 69 00 73 00 73 00 69 00 } //This might be a string? Looks like:issi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x177 = { 6E 00 74 00 61 00 69 00 } //This might be a string? Looks like:ntai
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x178 = "STUVWXYZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x303 = { 67 3D 22 55 54 46 2D 38 } //This might be a string? Looks like:g="UTF-8
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x304 = "EnableVi" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 49 files
		$x179 = "nitializ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x180 = { 00 74 00 72 00 75 00 63 } //This might be a string? Looks like:truc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x181 = { 00 73 00 65 00 72 00 76 } //This might be a string? Looks like:serv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 17 files
		$x182 = { 6F 00 6E 00 20 00 6F 00 } //This might be a string? Looks like:on o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x183 = "VirtualA" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x184 = { 00 20 00 64 00 65 00 70 } //This might be a string? Looks like: dep
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 30 files
		$x305 = { 65 12 2E 4E 45 54 20 46 } //This might be a string? Looks like:e.NET F
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 19 files
		$x185 = "tDirecto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 19 files
		$x306 = { E0 89 08 B0 3F 5F 7F 11 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x307 = { 65 6D 62 6C 79 3E 00 00 } //This might be a string? Looks like:embly>
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x308 = "System.T" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 26 files
		$x186 = { 70 00 6F 00 72 00 74 00 } //This might be a string? Looks like:port
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x187 = { 00 6C 00 69 00 62 00 72 } //This might be a string? Looks like:libr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x188 = { 00 76 00 65 00 72 00 66 } //This might be a string? Looks like:verf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 23 files
		$x189 = { 61 00 6E 00 64 00 20 00 } //This might be a string? Looks like:and 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 16 files
		$x190 = { 00 65 00 71 00 75 00 65 } //This might be a string? Looks like:eque
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 37 files
		$x191 = "sembly x" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 25 files
		$x311 = { 14 FE 03 2B 01 16 0A 06 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x192 = { 54 00 61 00 73 00 6B 00 } //This might be a string? Looks like:Task
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x193 = { 61 00 69 00 6C 00 65 00 } //This might be a string? Looks like:aile
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 28 files
		$x314 = { 69 62 75 74 65 00 47 75 } //This might be a string? Looks like:ibuteGu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 12 files
		$x194 = "CreateCo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x195 = { 00 65 00 6E 00 74 00 69 } //This might be a string? Looks like:enti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x196 = { 00 4C 00 6F 00 63 00 61 } //This might be a string? Looks like:Loca
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x197 = { 00 72 00 20 00 64 00 65 } //This might be a string? Looks like:r de
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x316 = "s.Strong" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 18 files
		$x198 = { 00 43 00 75 00 72 00 72 } //This might be a string? Looks like:Curr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x317 = { 72 69 62 75 74 65 00 41 } //This might be a string? Looks like:ributeA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x318 = { 6C 65 00 52 75 6E 74 69 } //This might be a string? Looks like:leRunti
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 36 files
		$x319 = { 65 00 73 00 63 00 72 00 } //This might be a string? Looks like:escr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x199 = { 70 00 72 00 65 00 73 00 } //This might be a string? Looks like:pres
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x200 = { 00 73 00 20 00 70 00 61 } //This might be a string? Looks like:s pa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x201 = { 00 64 00 20 00 77 00 69 } //This might be a string? Looks like:d wi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 18 files
		$x202 = "CDEFGHIJ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 22 files
		$x203 = { 00 65 00 6C 00 65 00 63 } //This might be a string? Looks like:elec
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x204 = { 00 65 00 6E 00 20 00 64 } //This might be a string? Looks like:en d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 23 files
		$x205 = { 6F 00 72 00 72 00 65 00 } //This might be a string? Looks like:orre
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x206 = { 69 00 6E 00 74 00 65 00 } //This might be a string? Looks like:inte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 14 files
		$x207 = "rminateP" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x208 = { 00 70 00 65 00 63 00 69 } //This might be a string? Looks like:peci
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x209 = { 00 72 00 61 00 74 00 69 } //This might be a string? Looks like:rati
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x210 = "FileType" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 32 files
		$x320 = "Threadin" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x211 = { 6F 00 67 00 72 00 65 00 } //This might be a string? Looks like:ogre
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 16 files
		$x212 = { 00 6E 00 20 00 6E 00 6F } //This might be a string? Looks like:n no
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 33 files
		$x321 = { 00 2E 63 63 74 6F 72 00 } //This might be a string? Looks like:.cctor
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x213 = { 00 67 00 75 00 6D 00 65 } //This might be a string? Looks like:gume
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 14 files
		$x214 = "qrstuvwx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x215 = { 4E 00 6F 00 74 00 20 00 } //This might be a string? Looks like:Not 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 33 files
		$x325 = "stem.Col" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 30 files
		$x216 = { 00 74 00 65 00 64 00 2E } //This might be a string? Looks like:ted.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x217 = "WaitForS" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x218 = { 00 46 00 61 00 69 00 6C } //This might be a string? Looks like:Fail
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 39 files
		$x219 = { 63 65 70 74 69 6F 6E 00 } //This might be a string? Looks like:ception
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 15 files
		$x220 = "tAvailab" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x221 = { 6E 00 73 00 74 00 61 00 } //This might be a string? Looks like:nsta
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 20 files
		$x222 = { 65 00 72 00 76 00 65 00 } //This might be a string? Looks like:erve
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 34 files
		$x331 = { 00 01 00 43 00 6F 00 6D } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 34 files
		$x333 = "ThreadAt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 35 files
		$x334 = "Compilat" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x223 = "ProcessA" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x224 = { 72 00 65 00 20 00 61 00 } //This might be a string? Looks like:re a
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x225 = { 61 00 74 00 65 00 20 00 } //This might be a string? Looks like:ate 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5 Found in 41 files
		$x226 = { 00 2E 00 30 00 2E 00 30 } //This might be a string? Looks like:.0.0
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x227 = { 00 74 00 6F 00 20 00 72 } //This might be a string? Looks like:to r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x228 = { 00 69 00 64 00 65 00 20 } //This might be a string? Looks like:ide 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x339 = { 00 02 00 60 85 00 00 10 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x229 = { 20 00 6C 00 69 00 73 00 } //This might be a string? Looks like: lis
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x230 = { 00 6E 00 20 00 63 00 61 } //This might be a string? Looks like:n ca
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 46 files
		$x231 = { 00 72 00 69 00 70 00 74 } //This might be a string? Looks like:ript
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 25 files
		$x232 = { 61 00 6E 00 67 00 65 00 } //This might be a string? Looks like:ange
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x233 = "Complete" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 16 files
		$x234 = "01234567" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x235 = { 6C 00 6F 00 73 00 65 00 } //This might be a string? Looks like:lose
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 23 files
		$x236 = { 00 6F 00 61 00 64 00 20 } //This might be a string? Looks like:oad 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5 Found in 26 files
		$x237 = { 65 00 73 00 73 00 65 00 } //This might be a string? Looks like:esse
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x238 = { 65 00 74 00 43 00 6F 00 } //This might be a string? Looks like:etCo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 36 files
		$x347 = { 65 00 73 00 6F 00 75 00 } //This might be a string? Looks like:esou
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x239 = { 6F 00 76 00 65 00 72 00 } //This might be a string? Looks like:over
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x240 = { 00 43 00 6F 00 6E 00 73 } //This might be a string? Looks like:Cons
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 45 files
		$x241 = "Microsof" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 16 files
		$x242 = "referenc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x243 = { 6F 00 6E 00 20 00 69 00 } //This might be a string? Looks like:on i
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x244 = { 00 65 00 6E 00 74 00 20 } //This might be a string? Looks like:ent 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 28 files
		$x245 = { 00 49 00 6E 00 73 00 74 } //This might be a string? Looks like:Inst
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x246 = { 00 6E 00 75 00 61 00 72 } //This might be a string? Looks like:nuar
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 18 files
		$x247 = "QueryVal" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 33 files
		$x349 = "mblyFile" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x248 = { 61 00 72 00 63 00 68 00 } //This might be a string? Looks like:arch
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 28 files
		$x351 = { 78 65 4D 61 69 6E 00 6D } //This might be a string? Looks like:xeMainm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x249 = { 67 00 72 00 6F 00 75 00 } //This might be a string? Looks like:grou
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 35 files
		$x250 = { 22 31 2E 30 22 3E 0D 0A } //This might be a string? Looks like:"1.0">\r\n
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x251 = { 00 72 00 61 00 6E 00 63 } //This might be a string? Looks like:ranc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 21 files
		$x252 = { 65 00 74 00 65 00 20 00 } //This might be a string? Looks like:ete 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 15 files
		$x253 = "Translat" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x254 = { 46 00 4F 00 52 00 4D 00 } //This might be a string? Looks like:FORM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 34 files
		$x353 = { 00 6D 73 63 6F 72 6C 69 } //This might be a string? Looks like:mscorli
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 22 files
		$x255 = { 69 00 6E 00 67 00 73 00 } //This might be a string? Looks like:ings
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x256 = { 00 6F 00 20 00 72 00 65 } //This might be a string? Looks like:o re
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 28 files
		$x257 = "GetCurre" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x258 = { 00 6F 00 72 00 20 00 77 } //This might be a string? Looks like:or w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x259 = { 63 00 68 00 69 00 6E 00 } //This might be a string? Looks like:chin
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x260 = { 69 00 73 00 74 00 20 00 } //This might be a string? Looks like:ist 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 21 files
		$x261 = "tAssembl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 28 files
		$x356 = { 00 67 65 74 5F 43 75 6C } //This might be a string? Looks like:get_Cul
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 40 files
		$x262 = "mpatible" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 35 files
		$x357 = { 00 74 00 4E 00 61 00 6D } //This might be a string? Looks like:tNam
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 18 files
		$x263 = { 74 00 43 00 6F 00 6E 00 } //This might be a string? Looks like:tCon
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 21 files
		$x264 = { 72 00 6F 00 63 00 65 00 } //This might be a string? Looks like:roce
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 48 files
		$x359 = { 69 00 6E 00 67 00 46 00 } //This might be a string? Looks like:ingF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 19 files
		$x265 = { 00 72 00 6F 00 6D 00 20 } //This might be a string? Looks like:rom 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 27 files
		$x360 = "tPositio" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x266 = { 68 00 69 00 73 00 20 00 } //This might be a string? Looks like:his 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x267 = { 20 00 6E 00 75 00 6D 00 } //This might be a string? Looks like: num
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 31 files
		$x362 = "lyTradem" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 35 files
		$x364 = { 01 00 46 00 69 00 6C 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x268 = "argument" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 15 files
		$x269 = { 00 63 00 6C 00 75 00 64 } //This might be a string? Looks like:clud
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 16 files
		$x270 = { 66 00 65 00 72 00 65 00 } //This might be a string? Looks like:fere
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 18 files
		$x271 = { 00 61 00 73 00 73 00 69 } //This might be a string? Looks like:assi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 24 files
		$x272 = { 61 00 6C 00 69 00 7A 00 } //This might be a string? Looks like:aliz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 27 files
		$x365 = "ButtonBa" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 15 files
		$x273 = "stemTime" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x274 = { 6E 00 67 00 20 00 72 00 } //This might be a string? Looks like:ng r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x275 = { 00 65 00 6C 00 61 00 79 } //This might be a string? Looks like:elay
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 21 files
		$x366 = "get_Defi" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x276 = { 12 13 14 15 16 17 18 19 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 20 files
		$x277 = { 66 00 72 00 6F 00 6D 00 } //This might be a string? Looks like:from
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x278 = { 65 00 70 00 61 00 72 00 } //This might be a string? Looks like:epar
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 17 files
		$x279 = { 00 20 00 65 00 78 00 69 } //This might be a string? Looks like: exi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 37 files
		$x368 = { 65 00 72 00 73 00 69 00 } //This might be a string? Looks like:ersi
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 17 files
		$x280 = { 01 02 03 04 05 06 07 08 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x281 = { 00 65 00 72 00 74 00 20 } //This might be a string? Looks like:ert 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 20 files
		$x282 = "etProcAd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 26 files
		$x370 = "mblyConf" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 15 files
		$x283 = { 65 74 45 76 65 6E 74 00 } //This might be a string? Looks like:etEvent
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x284 = { 00 20 00 61 00 6E 00 64 } //This might be a string? Looks like: and
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 16 files
		$x285 = { 74 00 20 00 69 00 73 00 } //This might be a string? Looks like:t is
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 22 files
		$x372 = { 00 00 42 53 4A 42 01 00 } //This might be a string? Looks like:BSJB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 27 files
		$x373 = "SetCompa" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 27 files
		$x374 = { 00 30 00 08 00 01 00 46 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 23 files
		$x375 = { 70 6F 6E 65 6E 74 73 00 } //This might be a string? Looks like:ponents
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 31 files
		$x376 = { 00 49 6E 76 6F 6B 65 00 } //This might be a string? Looks like:Invoke
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 14 files
		$x286 = { 20 00 6E 00 6F 00 6E 00 } //This might be a string? Looks like: non
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x287 = { 6E 00 74 00 20 00 73 00 } //This might be a string? Looks like:nt s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 29 files
		$x378 = "_Culture" ascii

		condition:
(288 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83,$x84,$x85,$x86,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x106,$x107,$x108,$x109,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x133,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x198,$x199,$x200,$x201,$x202,$x203,$x204,$x205,$x206,$x207,$x208,$x209,$x210,$x211,$x212,$x213,$x214,$x215,$x216,$x217,$x218,$x219,$x220,$x221,$x222,$x223,$x224,$x225,$x226,$x227,$x228,$x229,$x230,$x231,$x232,$x233,$x234,$x235,$x236,$x237,$x238,$x239,$x240,$x241,$x242,$x243,$x244,$x245,$x246,$x247,$x248,$x249,$x250,$x251,$x252,$x253,$x254,$x255,$x256,$x257,$x258,$x259,$x260,$x261,$x262,$x263,$x264,$x265,$x266,$x267,$x268,$x269,$x270,$x271,$x272,$x273,$x274,$x275,$x276,$x277,$x278,$x279,$x280,$x281,$x282,$x283,$x284,$x285,$x286,$x287) ) or (72 of ($x288,$x289,$x290,$x291,$x2,$x292,$x293,$x294,$x295,$x296,$x154,$x157,$x297,$x158,$x298,$x299,$x300,$x301,$x168,$x302,$x31,$x303,$x304,$x179,$x305,$x306,$x307,$x39,$x308,$x41,$x309,$x191,$x46,$x310,$x311,$x312,$x313,$x314,$x315,$x316,$x317,$x318,$x319,$x55,$x320,$x321,$x322,$x323,$x324,$x325,$x326,$x327,$x328,$x329,$x330,$x331,$x332,$x333,$x334,$x335,$x226,$x336,$x337,$x78,$x79,$x338,$x339,$x340,$x231,$x341,$x89,$x342,$x343,$x344,$x345,$x346,$x347,$x101,$x241,$x348,$x349,$x350,$x351,$x250,$x352,$x353,$x354,$x355,$x356,$x116,$x262,$x357,$x358,$x359,$x360,$x361,$x362,$x363,$x364,$x365,$x366,$x367,$x368,$x369,$x370,$x371,$x372,$x373,$x374,$x375,$x376,$x377,$x378) )}