import "pe"

rule SUS_PE_RelocSectionNoRelocation_Jan25
{
    meta:
        description = "Detects PE file with a .Reloc section and no relocation  - replicates Malcat RelocSectionNoRelocation"
        author = "Matt Green - @mgreen27"
        date = "2025-01-19"
    condition:
	uint16(0) == 0x5A4D and
	for any section in pe.sections : (
            section.name == ".reloc"
            and section.number_of_relocations == 0
	    and not for any dir in pe.data_directories : (
                section.virtual_address == dir.virtual_address
            )
        )
}
