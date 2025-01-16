SUS_MSC_Icon_Pdf_Jan25
{
    meta:
        description = "Detects MSC with suspicious PDF icon observed in use by APT"
        note = "Categorising as SUS as unknown if this icon is unique to the actor or generic PDF stored in msc during build. Add other icon sizes for completeness."
        author = "Matt Green - @mgreen27"
        hash = "ca0dfda9a329f5729b3ca07c6578b3b6560e7cfaeff8d988d1fe8c9ca6896da5"
        date = "2025-01-16"
    strings:
        $xml = "<?xml"
        $pdf_console_file_icon_small = "SUwBAQEABAAEABAAEAD/////IQD//////////0JNNgAAAAAAAAA2AAAAKAAAAEAAAAAQAAAAAQAgAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkpGQ/5CQj/+Pjo3/jo2M/4yMiv+Lion/iomH/4iHhv+HhoT/hYWD/4SDgf+DgoD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$
    condition:
        $xml at 0
        and $pdf_cons
}
