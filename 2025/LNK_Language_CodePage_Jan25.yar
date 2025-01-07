rule LNK_Languages_CodePage_Jan25
{
    meta:
        description = "Detects LNK with CodePage attribute - print strings to see value (remember to swap enndianess)"
        author = "Matt Green - @mgreen27"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b959e24d-67c7-4409-b52d-49c00f8bedf9"
        date = "2025-01-07"
    strings:
        $codepage_header = {0C 00 00 00 04 00 00 A0 ?? ?? ?? ??}
    condition:
        uint32be(0x0) == 0x4C000000 and $codepage_header
}

rule LNK_Languages_CodePage_Korean_Jan25
{
    meta:
        description = "Detects LNK with CodePage attribute for Korean"
        author = "Matt Green - @mgreen27"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b959e24d-67c7-4409-b52d-49c00f8bedf9"
        date = "2025-01-07"
    strings:
	$codepage_header = {0C 00 00 00 04 00 00 A0 }
    condition:
        uint32be(0x0) == 0x4C000000 and $codepage_header
	and uint32(@codepage_header + 8) == 949
}

rule LNK_Languages_CodePage_Chinese_Jan25
{
    meta:
        description = "Detects LNK with CodePage attribute for Chinese"
        author = "Matt Green - @mgreen27"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b959e24d-67c7-4409-b52d-49c00f8bedf9"
        date = "2025-01-07"
    strings:
        $codepage_header = {0C 00 00 00 04 00 00 A0 }
    condition:
        uint32be(0x0) == 0x4C000000 and $codepage_header
	and (
		uint32(@codepage_header + 8) == 936 //Simplified Chinese
        	or uint32(@codepage_header + 8) == 950 //Traditional Chinese
	)
}

rule LNK_Languages_CodePage_Cyrillic_Jan25
{
    meta:
        description = "Detects LNK with CodePage attribute for Cyrillic"
        author = "Matt Green - @mgreen27"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b959e24d-67c7-4409-b52d-49c00f8bedf9"
        date = "2025-01-07"
    strings:
        $codepage_header = {0C 00 00 00 04 00 00 A0 }
    condition:
        uint32be(0x0) == 0x4C000000 and $codepage_header
        and uint32(@codepage_header + 8) == 866
}

rule LNK_Languages_CodePage_Japanese_Jan25
{
    meta:
        description = "Detects LNK with CodePage attribute for Japanese"
        author = "Matt Green - @mgreen27"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b959e24d-67c7-4409-b52d-49c00f8bedf9"
        date = "2025-01-07"
    strings:
        $codepage_header = {0C 00 00 00 04 00 00 A0 }
    condition:
        uint32be(0x0) == 0x4C000000 and $codepage_header
        and uint32(@codepage_header + 8) == 932
}
