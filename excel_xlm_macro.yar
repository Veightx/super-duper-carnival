rule Excel_XLM_Macro_Obfuscation {
    meta:
        description = "Detects legacy Excel 4.0 (XLM) macros"
        severity = "high"
    strings:
        // 1. The Magic Header for Excel Binary (OLE)
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // 2. Dangerous Strings (ASCII and Wide for Unicode)
        $func1 = "FORMULA.FILL" ascii wide nocase
        $func2 = "Auto_Open" ascii wide nocase
        
        // 3. Common Excel Macro Sheet indicators
        // "Boundsheet" record often indicates a macro sheet in BIFF8
        $biff_macro = { 85 00 ?? ?? ?? ?? ?? ?? 01 00 } // Byte pattern for Macro sheet
        
    condition:
        // Match if it looks like an Excel file AND has dangerous strings
        ($ole_magic at 0) and ($func1 or $func2)
}
