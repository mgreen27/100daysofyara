rule EXPL_MEM_AmsiScanBuffer_Jan25 {
    meta:
        description = "Detects AmsiScanBuffer bypass in clr.dll mapped memory sections."
        author = "Matt Green - @mgreen27"
        date = "2025-01-22"
        reference = "https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/"
        note = "This rule is written for Velociraptor!"
        artifact = "Windows.System.VAD - target clr.dll mapped sections"
    strings:
        $amsi = { 
            61 00 6d 00 73 00 69 00 2e 00 64 00 6c 00 6c 00 // amsi.dll
            00 00 00 00 00 00 00 00 [16] 
            44 00 6f 00 74 00 4e 00 65 00 74 00 00 00 00 00 // DotNet
            41 6d 73 69 49 6e 69 74 69 61 6c 69 7a 65 // AmsiInitialize
        }
	$scanbuffer = "AmsiScanBuffer" ascii
    condition:
        $amsi and not $scanbuffer
}
