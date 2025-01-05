import "pe"

rule SUS_Renamed_QEMU_jan25 {
    meta:
        author = "Matt Green - @mgreen27"
        description = "Detects renamed QEMU exe used in crontrap example"
        date = "2025-01-05"
        reference = "https://www.securonix.com/blog/crontrap-emulated-linux-environments-as-the-latest-tactic-in-malware-staging/"
    condition:
        uint16(0) == 0x5A4D
        and (
		( pe.version_info["InternalName"] == "qemu" or pe.version_info["ProductName"] =="QUEMU" )
		or  for any sig in pe.signatures : (
            		sig.signer_info.program_name contains "QEMU"
        		)
	)
	and not filename == "qemu-system-x86_64.exe"
}
