rule sus_crontrap_img_jan25 {
    meta:
        author = "Matt Green - @mgreen27"
        description = "Detects suspicious tinycore linux image by checking for MBR header at offset 510 and tinycore strings"
        date = "2025-01-04"
        reference = "https://www.securonix.com/blog/crontrap-emulated-linux-environments-as-the-latest-tactic-in-malware-staging/"
    strings:
        $mbr_msg = "Missing operating system"
        $kernel_file = "vmlinuz"
        $tiny = "tinycore64"
        $tiny2 = "tc@box"

    condition:
        uint16(510) == 0xAA55 and $mbr_msg in (0..510)
        and filesize >= 200MB and filesize <=300MB
        and $kernel_file and 1 of ($tiny*)
}
