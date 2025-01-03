//Several rules created whilst exploring yara-x

import "lnk"

rule lnk_crontrap_jan25 {
    meta:
        description = "Detects LNK files associated to CRON#TRAP campaign"
        author = "Matt Green - @mgreen27"
        date = "2025-01-03"
        reference = "https://www.securonix.com/blog/crontrap-emulated-linux-environments-as-the-latest-tactic-in-malware-staging/"
    condition:
        lnk.tracker_data.machine_id == "desktop-uhmk71t"
        or lnk.drive_serial_number == 3774635658
}

rule lnk_crontrap_like_jan25 {
    meta:
        description = "Detects LNK files with similar powershell to CRON#TRAP campaign"
        author = "Matt Green - @mgreen27"
        date = "2025-01-03"
        reference = "https://www.securonix.com/blog/crontrap-emulated-linux-environments-as-the-latest-tactic-in-malware-staging/"
    condition:
        lnk.cmd_line_args contains "-windowstyle hidden -c Expand-Archive -Path"
        and lnk.cmd_line_args contains "; Invoke-Command {cmd.exe /c"
        and lnk.cmd_line_args icontains ".bat"
}
