rule SUS_PE_PossiblePackerApiDynamicImport_Jan25
{
    meta:
        description = "Detects a PE file with packer related API strings and no import - replicates Malcat PossiblePackerApiDynamicImport"
        author = "Matt Green - @mgreen27"
        date = "2025-01-30"
        reference = "https://doc.malcat.fr/analysis/anomalies-list.html"
    strings:
        $kernel32_1 = "VirtualProtect" ascii wide
        $kernel32_2 = "VirtualProtectEx" ascii wide
        $kernel32_3 = "VirtualAlloc" ascii wide
        $kernel32_4 = "VirtualAllocEx" ascii wide
        $kernel32_5 = "VirtualAllocExNuma" ascii wide
        $kernel32_6 = "ResumeThread" ascii wide
        $kernel32_7 = "SetThreadContext" ascii wide
        $kernel32_8 = "FindResourceA" ascii wide
        $kernel32_9 = "LockResource" ascii wide
        $kernel32_10 = "LoadResource" ascii wide
        $ntdll_1 = "LdrAccessResource" ascii wide
        $ntdll_2 = "LdrFindResource_U" ascii wide
        $ntdll_3 = "NtResumeThread" ascii wide
        $ntdll_4 = "NtAllocateVirtualMemory" ascii wide
        $ntdll_5 = "NtMapViewOfSection" ascii wide
        $ntdll_6 = "NtProtectVirtualMemory" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and (
            ( $kernel32_1 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","VirtualProtect") > 0 ) or
            ( $kernel32_2 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","VirtualProtectEx") > 0 ) or
            ( $kernel32_3 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","VirtualAlloc") > 0 ) or
            ( $kernel32_4 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","VirtualAllocEx") > 0 ) or
            ( $kernel32_5 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","VirtualAllocExNuma") > 0 ) or
            ( $kernel32_6 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","ResumeThread") > 0 ) or
            ( $kernel32_7 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","SetThreadContext") > 0 ) or
            ( $kernel32_8 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","FindResourceA") > 0 ) or
            ( $kernel32_9 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","LockResource") > 0 ) or
            ( $kernel32_10 and not pe.imports(pe.IMPORT_ANY,"kernel32.dll","LoadResource") > 0 ) or
            ( $ntdll_1 and not pe.imports(pe.IMPORT_ANY,"ntdll.dll","LdrAccessResource") > 0 ) or
            ( $ntdll_2 and not pe.imports(pe.IMPORT_ANY,"ntdll.dll","LdrFindResource_U") > 0 ) or
            ( $ntdll_3 and not pe.imports(pe.IMPORT_ANY,"ntdll.dll","NtResumeThread") > 0 ) or
            ( $ntdll_4 and not pe.imports(pe.IMPORT_ANY,"ntdll.dll","NtAllocateVirtualMemory") > 0 ) or
            ( $ntdll_5 and not pe.imports(pe.IMPORT_ANY,"ntdll.dll","NtMapViewOfSection") > 0 ) or
            ( $ntdll_6 and not pe.imports(pe.IMPORT_ANY,"ntdll.dll","NtProtectVirtualMemory") > 0 )
        )
}
