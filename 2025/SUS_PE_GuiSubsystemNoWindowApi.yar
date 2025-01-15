import "pe"

rule SUS_PE_GuiSubsystemNoWindowApi_Jan25
{
    meta:
        description = "Detects PE file with SUBSYSTEM_WINDOWS_GUI but no imported Window APIs - replicate Malcat GuiSubsystemNoWindowApi"
        author = "Matt Green - @mgreen27"
        reference = "https://doc.malcat.fr/analysis/anomalies-list.html"
        date = "2025-01-15"
    condition:
        uint16(0) == 0x5A4D
        and pe.subsystem == 2 // SUBSYSTEM_WINDOWS_GUI

	// Check for any Window APIs - add as needed - Regex used to limit pe.imports() calls.
        and not pe.imports(/user32.dll/i,/(CreateWindow|CreateDialogIndirectParam|DialogBoxIndirectParam|DialogBoxParam|DispatchMessage|DefDlgProc|MessageBox|GetDC)/i) > 0
}
