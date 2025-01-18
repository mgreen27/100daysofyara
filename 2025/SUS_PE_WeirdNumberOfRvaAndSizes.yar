import "pe"

rule SUS_PE_WeirdNumberOfRvaAndSizes_Jan25
{
    meta:
        description = "Detects PE file with suspicious Number of RVA and Sizes attribute. NumberofRVAandSizes > 16 or NumberofRVAandSizes < 10 - replicates Malcat WeirdNumberOfRvaAndSizes"
        author = "Matt Green - @mgreen27"
        date = "2025-01-18"
    condition:
	pe.number_of_rva_and_sizes > 16 or pe.number_of_rva_and_sizes < 10
}
