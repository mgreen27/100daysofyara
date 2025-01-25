import "pe"

rule SUS_PE_MicrosoftTeamsNotSignedByMicrosoft_Jan25 {
    meta:
        description = "Detects PE files masquerading as Microsoft Teams not signed by Microsoft"
        author = "Matt Green - @mgreen27"
        date = "2025-01-24"
	reference = "https://x.com/SquiblydooBlog/status/1881853095262761471"
    condition:
        uint16(0) == 0x5A4D
	and pe.version_info["ProductName"] == "Microsoft Teams"
        and not pe.signatures[0].subject contains "CN=Microsoft Corporation"
        and not pe.signatures[0].issuer contains "Microsoft Corporation"
}

rule MAL_MaliciousSigner_AnalyserEnterprises_Jan25 {
    meta:
        description = "Detects low detection CobaltStrike PE by certificate metadata"
        author = "Matt Green - @mgreen27"
        date = "2025-01-24"
	reference = "https://x.com/SquiblydooBlog/status/1881853095262761471"
    condition:
        uint16(0) == 0x5A4D
        and ( pe.signatures[0].subject contains "ANALYZER ENTERPRISES LLP"
                or pe.signatures[0].subject contains "fvakdu@gmail.com" )
}
