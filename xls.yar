rule Suspicious_Excel_XLM_Macro_Sheet {
    meta:
        description = "Detects the presence of legacy Excel 4.0 Macro Sheets (High Fidelity for Malware)"
        severity = "high"
        author = "Sublime User"
    
    strings:
        // 1. Modern Excel (.xlsm) - Looks for the internal XML part defining a macro sheet
        // These files are actually Zips; Sublime's file.explode will unzip them to find this.
        $xml_macro = "application/vnd.ms-excel.macrosheet" ascii nocase

        // 2. Binary Excel (.xls) - The "Boundsheet" Record (0x85)
        // 0x0085 = Record Type, 0x0040 = Macro Sheet Type
        // We look for the sequence: 85 00 (Record) ... (skip len) ... 40 00 (Type)
        // This is a rough binary signature for "There is a macro sheet here"
        $bin_macro_header = { 85 00 ?? ?? ?? ?? 40 00 }

    condition:
        // Trigger if we find either the XML definition or the Binary definition
        $xml_macro or $bin_macro_header
}
