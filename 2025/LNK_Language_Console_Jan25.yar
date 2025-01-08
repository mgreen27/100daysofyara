rule LNK_Languages_Console_Korean_Jan25
{
    meta:
        description = "Detects LNK with Korean language font in UTF-16LE encoding the FaceName console attribute"
        author = "Matt Green - @mgreen27"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b959e24d-67c7-4409-b52d-49c00f8bedf9"
        date = "2025-01-08"
    strings:
        $console = { CC 00 00 00 02 00 00 A0 }

	$kr_gulimche = { 74 AD BC B9 B4 CC }  // 굴림체
        $kr_batangche = { 14 BC D5 D0 B4 CC } // 바탕체
        $kr_dotumche = { CB B3 C0 C6 B4 CC }  // 돋움체
        $kr_gungsuhche = { 81 AD 1C C1 B4 CC } // 궁서체

    condition:
        uint32be(0x0) == 0x4C000000 and $console
	and 1 of ($kr_*) at ( @console + 44 )
}
