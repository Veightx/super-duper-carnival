rule Excel_XLM_Macro_Hybrid {
    meta:
        description = "Detects Excel 4.0 (XLM) Macros in both Binary (.xls) and XML (.xlsm) formats"
        severity = "high"
        author = "User"

    strings:
        // --- CASE 1: Modern XML Format (.xlsm) ---
        // In XML, these are just text strings inside 'macrosheets/sheet1.xml'
        $xml_tag     = "<macrosheet" ascii nocase
        $xml_formula = "FORMULA.FILL" ascii nocase
        
        // --- CASE 2: Legacy Binary Format (.xls) ---
        // We look for the "BOUNDSHEET" record (0x0085)
        // Structure: [85 00] [Len] [Offset] [Hidden?] [Type]
        // Type 01 = Excel 4.0 Macro Sheet (The Smoking Gun)
        // Wildcards (??) skip the variable length/offset bytes
        $binary_macro_sheet = { 85 00 ?? ?? ?? ?? ?? 01 }

        // Optional: Look for the specific "FORMULA.FILL" Opcode in BIFF8
        // Opcode for FORMULA is usually complicated, but the sheet type (above) is reliable.

    condition:
        // Trigger if we find the XML signature OR the Binary signature
        $xml_tag or $xml_formula or $binary_macro_sheet
}
