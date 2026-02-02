rule malware_samples_formbook
{
	//Input TP Rate:
	//36/50
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.897979296672176 Found in 11 files
		$x0 = { 49 64 00 00 67 03 4D 75 6C 74 69 42 79 74 65 54 6F 57 69 64 65 43 68 61 72 00 66 03 4D 75 6C 44 69 76 00 00 A4 02 47 65 74 56 65 72 73 69 6F 6E 45 78 57 00 0E 03 49 73 57 6F 77 36 34 50 72 6F } //This might be a string? Looks like:IdgMultiByteToWideCharfMulDivGetVersionExWIsWow64Pro
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.9375 Found in 17 files
		$x1 = { 7B A0 5C B3 2B C0 7E 18 CC 94 DD 66 BB 04 AB 8D DF E8 55 69 48 29 D6 B7 48 A1 61 54 AC CE 56 A2 2C A9 80 4B BA 50 F0 D8 5F 47 84 1A B1 5D BF 59 2C AA D2 E1 2E C6 32 8C 9B 60 1C 9D 78 39 AF BD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.113204882778696 Found in 18 files
		$x17 = { 6E 00 74 00 75 00 6D 00 20 00 62 00 72 00 65 00 61 00 63 00 68 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 2E 00 00 01 00 15 49 00 6D 00 70 00 6F 00 73 00 73 00 69 00 62 00 6C 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6719731490673295 Found in 26 files
		$x18 = { 61 6D 65 77 6F 72 6B 2C 56 65 72 73 69 6F 6E 3D 76 34 2E 35 01 00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C 61 79 4E 61 6D 65 12 2E 4E 45 54 20 46 72 61 6D 65 77 6F 72 6B 20 34 2E 35 } //This might be a string? Looks like:amework,Version=v4.5TFrameworkDisplayName.NET Framework 4.5
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.814027824422272 Found in 19 files
		$x19 = { 75 69 64 41 74 74 72 69 62 75 74 65 00 47 65 6E 65 72 61 74 65 64 43 6F 64 65 41 74 74 72 69 62 75 74 65 00 44 65 62 75 67 67 65 72 4E 6F 6E 55 73 65 72 43 6F 64 65 41 74 74 72 69 62 75 74 65 } //This might be a string? Looks like:uidAttributeGeneratedCodeAttributeDebuggerNonUserCodeAttribute
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.416277399432949 Found in 5 files
		$x10 = { 02 00 40 00 01 00 00 00 FF FF FF FF 01 00 00 00 00 00 00 00 0C 02 00 00 00 51 53 79 73 74 65 6D 2E 44 72 61 77 69 6E 67 2C 20 56 65 72 73 69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20 43 75 6C 74 75 } //This might be a string? Looks like:@QSystem.Drawing, Version=4.0.0.0, Cultu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.60845859334435 Found in 6 files
		$x11 = { 65 6E 3D 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 23 53 79 73 74 65 6D 2E 52 65 73 6F 75 72 63 65 73 2E 52 75 6E 74 69 6D 65 52 65 73 6F 75 72 63 65 53 65 74 02 00 00 00 03 00 00 00 01 } //This might be a string? Looks like:en=b77a5c561934e089#System.Resources.RuntimeResourceSet
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4394426583779896 Found in 5 files
		$x12 = { 43 01 03 04 04 05 04 05 09 05 05 09 14 0D 0B 0D 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 14 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 6.0 Found in 14 files
		$x6 = { 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 5B 5C 5D 5E 5F 60 } //This might be a string? Looks like:!"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\]^_`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.96875 Found in 22 files
		$x20 = { 51 B0 FF 78 27 AB FF E5 F0 56 FF 76 55 44 FF 06 D4 22 FF 4B 3D BC FF 53 21 97 FF DA 60 38 FF 39 EC 0B FF D1 17 46 FF 45 95 49 FF F5 5D 80 FF BD 6B B8 FF 7F A6 4F FF 65 33 CE FF 45 05 1E FF 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9918827203902905 Found in 20 files
		$x21 = { 75 74 65 00 44 65 62 75 67 67 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 45 64 69 74 6F 72 42 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 43 6F 6D 56 69 73 69 62 6C 65 41 74 74 72 69 } //This might be a string? Looks like:uteDebuggableAttributeEditorBrowsableAttributeComVisibleAttri
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.823684179450872 Found in 10 files
		$x22 = { 00 11 43 6F 70 79 72 69 67 68 74 20 C2 A9 20 32 30 32 34 00 00 29 01 00 24 61 31 62 32 63 33 64 34 2D 65 35 66 36 2D 34 61 35 62 2D 38 63 39 64 2D 30 65 31 66 32 61 33 62 34 63 35 64 00 00 0C } //This might be a string? Looks like:Copyright  2024)$a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9326114862707113 Found in 8 files
		$x16 = { 6F 6E 74 72 6F 6C 43 6F 6C 6C 65 63 74 69 6F 6E 00 4F 62 6A 65 63 74 43 6F 6C 6C 65 63 74 69 6F 6E 00 73 65 74 5F 53 74 61 72 74 50 6F 73 69 74 69 6F 6E 00 46 6F 72 6D 53 74 61 72 74 50 6F 73 } //This might be a string? Looks like:ontrolCollectionObjectCollectionset_StartPositionFormStartPos
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.149332374824754 Found in 6 files
		$x8 = { 62 6C 65 54 65 78 74 52 65 6E 64 65 72 69 6E 67 44 65 66 61 75 6C 74 00 44 69 61 6C 6F 67 52 65 73 75 6C 74 00 43 6F 6E 74 65 6E 74 41 6C 69 67 6E 6D 65 6E 74 00 45 6E 76 69 72 6F 6E 6D 65 6E } //This might be a string? Looks like:bleTextRenderingDefaultDialogResultContentAlignmentEnvironmen
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.3667292966721747 Found in 13 files
		$x2 = { FF 00 00 FF FF 00 00 FF FF 00 00 C0 07 00 00 DF F7 00 00 DF F7 00 00 DE F7 00 00 DE F7 00 00 D8 37 00 00 DE F7 00 00 DE F7 00 00 DF F7 00 00 DF F7 00 00 C0 07 00 00 FF FF 00 00 FF FF 00 00 28 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9564544943098365 Found in 23 files
		$x23 = { 73 75 61 6C 53 74 75 64 69 6F 2E 45 64 69 74 6F 72 73 2E 53 65 74 74 69 6E 67 73 44 65 73 69 67 6E 65 72 2E 53 65 74 74 69 6E 67 73 53 69 6E 67 6C 65 46 69 6C 65 47 65 6E 65 72 61 74 6F 72 09 } //This might be a string? Looks like:sualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator\t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.9971748520721246 Found in 24 files
		$x24 = "crosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFile" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.2893133835099375 Found in 25 files
		$x25 = { 6F 6E 52 65 6C 61 78 61 74 69 6F 6E 73 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 50 72 6F 64 75 63 74 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 43 6F 70 79 72 69 67 68 } //This might be a string? Looks like:onRelaxationsAttributeAssemblyProductAttributeAssemblyCopyrigh
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.91627739943295 Found in 9 files
		$x26 = { 0B 9E 3B FF 83 B7 40 FF 87 73 F2 FF C0 BF 65 FF 86 47 90 FF 77 AB 1F FF DE B6 DC FF 0A 9C A5 FF CA 14 8B FF 48 D0 1B FF 3A 82 6E FF 57 97 97 FF EC D0 A3 FF D4 56 CF FF AC 4D E4 FF 0B 00 00 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7703202953006736 Found in 12 files
		$x3 = { 00 88 8F 00 00 F7 11 00 00 76 77 00 00 77 8F 00 00 FF FF 00 00 F7 11 00 00 68 67 00 00 86 8F 00 00 88 8F 00 00 F7 11 00 00 76 86 00 00 68 8F 00 00 FF FF FF FF F7 11 28 00 00 00 30 00 00 00 60 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 14 files
		$x4 = { 52 FF 89 9A 53 FF 88 9B 54 FF 87 9D 55 FF 85 9E 56 FF 84 A0 57 FF 83 A1 58 FF 81 A3 59 FF 80 A4 5A FF 7F A6 5B FF 7D A7 5D FF 7C A9 5E FF 7B AA 5F FF 79 AB 60 FF 78 AC 61 FF 77 AE 62 FF D1 BD } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.333668704467279 Found in 26 files
		$x27 = { 53 79 73 74 65 6D 2E 52 75 6E 74 69 6D 65 2E 49 6E 74 65 72 6F 70 53 65 72 76 69 63 65 73 00 4D 69 63 72 6F 73 6F 66 74 2E 56 69 73 75 61 6C 42 61 73 69 63 2E 43 6F 6D 70 69 6C 65 72 53 65 72 } //This might be a string? Looks like:System.Runtime.InteropServicesMicrosoft.VisualBasic.CompilerSer
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.905639062229567 Found in 29 files
		$x28 = { 69 63 4B 65 79 54 6F 6B 65 6E 3D 62 30 33 66 35 66 37 66 31 31 64 35 30 61 33 61 05 01 00 00 00 15 53 79 73 74 65 6D 2E 44 72 61 77 69 6E 67 2E 42 69 74 6D 61 70 01 00 00 00 04 44 61 74 61 07 } //This might be a string? Looks like:icKeyToken=b03f5f7f11d50a3aSystem.Drawing.BitmapData
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.675704882778696 Found in 5 files
		$x14 = { FE 01 12 FF 06 11 02 FF 65 36 78 FF E9 D1 20 FF 7E B7 20 FF E0 C8 20 FF 1E 91 00 FF 25 AD EF FF 1B 59 04 FF 00 04 7B FF 61 D8 C4 FF 08 7D 14 FF 1E 06 0B FF E9 08 CF FF 1A 7B 02 FF BF 44 B5 FF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.654078664259099 Found in 24 files
		$x29 = { 00 00 00 00 00 00 00 00 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 22 79 65 73 22 } //This might be a string? Looks like:<?xml version="1.0" encoding="UTF-8" standalone="yes"
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.758063383509937 Found in 13 files
		$x30 = { 35 01 00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C 61 79 4E 61 6D 65 12 2E 4E 45 54 20 46 72 61 6D 65 77 6F 72 6B 20 34 2E 35 04 01 00 00 00 41 01 00 33 53 79 73 74 65 6D 2E 52 65 73 } //This might be a string? Looks like:5TFrameworkDisplayName.NET Framework 4.5A3System.Res
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.128928031846025 Found in 14 files
		$x31 = { 73 73 65 6D 62 6C 79 50 72 6F 64 75 63 74 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 43 6F 70 79 72 69 67 68 74 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 43 6F 6D 70 61 } //This might be a string? Looks like:ssemblyProductAttributeAssemblyCopyrightAttributeAssemblyCompa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.7646644531567945 Found in 23 files
		$x32 = { 69 6D 65 52 65 73 6F 75 72 63 65 53 65 74 02 00 00 00 00 00 00 00 00 00 00 00 50 41 44 50 41 44 50 B4 00 00 00 B4 00 00 00 CE CA EF BE 01 00 00 00 91 00 00 00 6C 53 79 73 74 65 6D 2E 52 65 73 } //This might be a string? Looks like:imeResourceSetPADPADPlSystem.Res
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.984473149067328 Found in 22 files
		$x33 = { 6F 6E 55 73 65 72 43 6F 64 65 41 74 74 72 69 62 75 74 65 00 44 65 62 75 67 67 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 45 64 69 74 6F 72 42 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 } //This might be a string? Looks like:onUserCodeAttributeDebuggableAttributeEditorBrowsableAttribute
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.17070839910992 Found in 17 files
		$x34 = { 63 72 69 70 74 69 6F 6E 41 74 74 72 69 62 75 74 65 00 43 6F 6D 70 69 6C 61 74 69 6F 6E 52 65 6C 61 78 61 74 69 6F 6E 73 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6D 62 6C 79 50 72 6F 64 75 63 } //This might be a string? Looks like:criptionAttributeCompilationRelaxationsAttributeAssemblyProduc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.238675277061448 Found in 21 files
		$x35 = { FE 01 13 13 11 13 2C 13 00 11 12 1F 0D 5D 13 14 11 14 20 AA 00 00 00 61 13 14 00 00 11 05 17 58 13 05 38 B6 FE FF FF 00 11 04 17 58 13 04 16 13 05 11 04 06 61 19 5F 13 16 11 16 13 15 11 15 45 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.132452445739504 Found in 25 files
		$x36 = { 61 6C 42 61 73 69 63 2E 43 6F 6D 70 69 6C 65 72 53 65 72 76 69 63 65 73 00 53 79 73 74 65 6D 2E 52 75 6E 74 69 6D 65 2E 43 6F 6D 70 69 6C 65 72 53 65 72 76 69 63 65 73 00 53 79 73 74 65 6D 2E } //This might be a string? Looks like:alBasic.CompilerServicesSystem.Runtime.CompilerServicesSystem.
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.882856063692049 Found in 28 files
		$x37 = { 61 74 65 64 43 6F 64 65 41 74 74 72 69 62 75 74 65 00 44 65 62 75 67 67 65 72 4E 6F 6E 55 73 65 72 43 6F 64 65 41 74 74 72 69 62 75 74 65 00 44 65 62 75 67 67 61 62 6C 65 41 74 74 72 69 62 75 } //This might be a string? Looks like:atedCodeAttributeDebuggerNonUserCodeAttributeDebuggableAttribu
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.101202445739503 Found in 11 files
		$x38 = { 47 6C 6F 62 61 6C 69 7A 61 74 69 6F 6E 00 53 79 73 74 65 6D 2E 52 65 66 6C 65 63 74 69 6F 6E 00 43 6F 6E 74 72 6F 6C 43 6F 6C 6C 65 63 74 69 6F 6E 00 73 65 74 5F 53 74 61 72 74 50 6F 73 69 74 } //This might be a string? Looks like:GlobalizationSystem.ReflectionControlCollectionset_StartPosit
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.978373781480404 Found in 11 files
		$x39 = { 2D 38 63 39 64 2D 30 65 31 66 32 61 33 62 34 63 35 64 00 00 0C 01 00 07 31 2E 30 2E 30 2E 30 00 00 49 01 00 1A 2E 4E 45 54 46 72 61 6D 65 77 6F 72 6B 2C 56 65 72 73 69 6F 6E 3D 76 34 2E 35 01 } //This might be a string? Looks like:-8c9d-0e1f2a3b4c5d1.0.0.0I.NETFramework,Version=v4.5
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6263530781525795 Found in 8 files
		$x13 = { 6F 6B 65 6E 3D 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 23 53 79 73 74 65 6D 2E 52 65 73 6F 75 72 63 65 73 2E 52 75 6E 74 69 6D 65 52 65 73 6F 75 72 63 65 53 65 74 02 00 00 00 03 00 00 } //This might be a string? Looks like:oken=b77a5c561934e089#System.Resources.RuntimeResourceSet
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.7829638216885835 Found in 23 files
		$x40 = { 00 00 0C 01 00 07 31 2E 30 2E 30 2E 30 00 00 49 01 00 1A 2E 4E 45 54 46 72 61 6D 65 77 6F 72 6B 2C 56 65 72 73 69 6F 6E 3D 76 34 2E 35 01 00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73 70 6C } //This might be a string? Looks like:1.0.0.0I.NETFramework,Version=v4.5TFrameworkDispl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.184424657837695 Found in 15 files
		$x41 = { 53 79 73 74 65 6D 2E 54 68 72 65 61 64 69 6E 67 00 4C 61 74 65 42 69 6E 64 69 6E 67 00 53 79 73 74 65 6D 2E 52 75 6E 74 69 6D 65 2E 56 65 72 73 69 6F 6E 69 6E 67 00 54 6F 53 74 72 69 6E 67 00 } //This might be a string? Looks like:System.ThreadingLateBindingSystem.Runtime.VersioningToString
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.8125 Found in 18 files
		$x7 = { 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 36 4D A8 FF 73 24 A7 3C F6 7A 12 F1 67 AC C1 93 E7 6B 43 CA 52 A6 AD 00 00 E1 BB 3A 21 A5 29 E3 EC E7 0B 98 2E 40 BD E1 9A DE 80 46 B1 9D 6B } 
		//Benign FP est: -8.7E-4 Malicious FP est: -0.0 Entropy: 6.0 Found in 6 files
		$x9 = { 75 76 77 78 79 7A 83 84 85 86 87 88 89 8A 92 93 94 95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 B7 B8 B9 BA C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E1 E2 E3 E4 E5 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.90625 Found in 17 files
		$x5 = { 0B 98 2E 40 BD E1 9A DE 80 46 B1 9D 6B 3B 21 D4 B1 D6 75 3A C8 3D C6 D0 33 F7 14 AF CB 17 A2 94 01 8D 13 88 FE 64 95 61 E7 B6 4D 62 F8 00 00 6C FE 74 84 6A 78 49 F1 B5 91 05 38 EE 76 1E F9 D2 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6499433125951875 Found in 26 files
		$x42 = { 69 6F 6E 3D 22 31 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 22 79 65 73 22 3F 3E 0D 0A 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C 6E 73 } //This might be a string? Looks like:ion="1.0" encoding="UTF-8" standalone="yes"?>\r\n\r\n<assembly xmlns
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.4936933125951875 Found in 22 files
		$x43 = { 72 63 65 42 75 69 6C 64 65 72 08 31 37 2E 30 2E 30 2E 30 00 00 5A 01 00 4B 4D 69 63 72 6F 73 6F 66 74 2E 56 69 73 75 61 6C 53 74 75 64 69 6F 2E 45 64 69 74 6F 72 73 2E 53 65 74 74 69 6E 67 73 } //This might be a string? Looks like:rceBuilder17.0.0.0ZKMicrosoft.VisualStudio.Editors.Settings
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.073433985216441 Found in 6 files
		$x15 = { 74 65 00 44 65 62 75 67 67 65 72 42 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 45 64 69 74 6F 72 42 72 6F 77 73 61 62 6C 65 41 74 74 72 69 62 75 74 65 00 43 6F 6D 56 69 73 69 62 6C } //This might be a string? Looks like:teDebuggerBrowsableAttributeEditorBrowsableAttributeComVisibl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.342888867995137 Found in 23 files
		$x44 = { 63 65 73 2E 52 75 6E 74 69 6D 65 52 65 73 6F 75 72 63 65 53 65 74 02 00 00 00 02 00 00 00 01 00 00 00 68 53 79 73 74 65 6D 2E 44 72 61 77 69 6E 67 2E 42 69 74 6D 61 70 2C 20 53 79 73 74 65 6D } //This might be a string? Looks like:ces.RuntimeResourceSethSystem.Drawing.Bitmap, System

		condition:
(7 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7) ) or (8 of ($x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16) ) or (20 of ($x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44) )}