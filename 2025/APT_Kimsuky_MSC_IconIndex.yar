rule APT_Kimsuky_MSC_IconIndex_Jan25
{
    meta:
        description = "Detects suspected Kimsuky msc file with unique Icon Index path."
        author = "Matt Green - @mgreen27"
        date = "2025-01-27"
	hash = "f7e29ad2b0d3da5c2a9fa8f54629cdd7b5b890a04b7408c7bdbd02e5772c5103"
    strings:
        $xml = "<?xml"
        $iconindex ="<Icon Index=\"0\" File=\"F:\\WINWORD.EXE\">"
    condition:
        $xml at 0 and $iconindex
}
