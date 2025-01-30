import "pe"

rule SUS_PE_PossibleDownloaderApiDynamicImport_Jan25
{
    meta:
        description = "Detects a PE file with downloader related API strings and no import - replicates Malcat PossibleDownloaderApiDynamicImport"
        author = "Matt Green - @mgreen27"
        date = "2025-01-29"
        reference = "https://doc.malcat.fr/analysis/anomalies-list.html"
    strings:
        $wininet1 = "InternetReadFile" ascii wide
        $wininet2 = "InternetConnectA" ascii wide
        $wininet3 = "InternetConnectW" ascii wide
        $other = "recv" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and (
            ( $wininet1 and not pe.imports(pe.IMPORT_ANY,"wininet.dll","InternetReadFile") > 0 ) or
            ( $wininet2 and not pe.imports(pe.IMPORT_ANY,"wininet.dll","InternetConnectA") > 0 ) or
            ( $wininet3 and not pe.imports(pe.IMPORT_ANY,"wininet.dll","InternetConnectW") > 0 ) or
            ( $other and not pe.imports(pe.IMPORT_ANY,"wsock32.dll","recv") > 0 ) or
            ( $other and not pe.imports(pe.IMPORT_ANY,"ws_32.dll","recv") > 0 )
        )
}
