rule SUS_Rclone_Memory_Jan25
{
    meta:
        author = "Matt Green - @mgreen27"
        description = "Detects Rclone in process memory. "
        date = "2025-01-10"
        reference = "https://github.com/rclone/rclone"
    strings:
        $go = "Go build ID:"
        $github = "github.com/rclone/rclone"
    condition:
        $go and
        @github >= 20
}
