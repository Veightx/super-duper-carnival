rule Excel_XLM_Macro_Obfuscation {
    meta:
        description = "Detects legacy Excel 4.0 (XLM) macros using dangerous execution functions"
        author = "User"
        severity = "high"
        reference = "Excel 4.0 Macro Obfuscation via FORMULA.FILL"
    
    strings:
        // The specific dangerous functions in XLM
        // We use 'nocase' because Excel isn't case-sensitive with these
        $func1 = "FORMULA.FILL" ascii wide nocase
        $func2 = "EXEC" ascii wide nocase
        $func3 = "REGISTER" ascii wide nocase
        $func4 = "HALT" ascii wide nocase
        
        // The auto-execution entry point for XLM
        $auto = "Auto_Open" ascii wide nocase
        
        // Common string obfuscation pattern in XLM (Char function)
        $char_obfu = "CHAR(" ascii wide nocase

    condition:
        // Match if we see the 'Auto_Open' trigger AND one of the dangerous functions
        ($auto and 1 of ($func*))
        
        // OR if we see the highly specific FORMULA.FILL command (rare in legitimate files)
        or $func1
}
