import "lnk"

rule SUS_LNK_Mshta_VBScript_Jan25 {
    meta:
        description = "Detects LNK files mshta vbscript methodology"
        version = "yara-x"
        author = "Matt Green - @mgreen27"
        date = "2025-01-31"
    condition:
    	uint32be(0x0) == 0x4C000000
    	and lnk.local_base_path iendswith "\\mshta.exe"
        and lnk.cmd_line_args icontains "javascript"
        and lnk.cmd_line_args icontains "ActiveXObject"
}
