import "pe"

rule SUS_PE_UnbalancedVirtualPysicalRatio_Jan25
{
    meta:
        description = "Detects PE file with large difference between physical and virtual size of a section - replicates Malcat UnbalancedVirtualPhysicalRatio"
        author = "Matt Green - @mgreen27"
	reference = "https://doc.malcat.fr/analysis/anomalies-list.html"
        date = "2025-01-23"
    condition:
	uint16(0) == 0x5A4D
        and for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].raw_data_size > 0 and            // Ensure SizeOfRawData is non-zero
                pe.sections[i].virtual_size > 0 and            // Ensure VirtualSize is non-zero
                (
                    pe.sections[i].virtual_size > pe.sections[i].raw_data_size + 0x10000 or  // VirtualSize much larger
                    pe.sections[i].raw_data_size > pe.sections[i].virtual_size + 0x10000    // RawDataSize much larger
                )
            )
}
