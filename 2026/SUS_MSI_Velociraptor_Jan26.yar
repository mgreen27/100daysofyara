rule sus_msi_velociraptor
{
    meta:
        author = "Matt Green - @mgreen27"
        description = "Detects unique strings in Velociraptor MSI files"
        date = "2025-1-07"

    strings:
        $msi1 = "ci_build_url:" ascii
        $msi2 = "build_time:" ascii
        $msi3 = "server_urls:" ascii
        $msi4 = "writeback_windows:" ascii
        $msi5 = "velociraptor" ascii
        $msi6 = "Velociraptor" ascii

    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1 and
        4 of ($msi*)
}


rule sus_msi_velociraptor_workersdev
{
    meta:
        author = "Matt Green - @mgreen27"
        description = "Detects Velociraptor MSI files with workers.dev"
        date = "2025-1-07"

    strings:
        $msi1 = "ci_build_url:" ascii
        $msi2 = "build_time:" ascii
        $msi3 = "server_urls:" ascii
        $msi4 = "writeback_windows:" ascii
        $msi5 = "velociraptor" ascii
        $msi6 = "Velociraptor" ascii
        
        $server_urls = ".workers.dev" ascii

    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1 and
        4 of ($msi*) and
        $server_urls
}
