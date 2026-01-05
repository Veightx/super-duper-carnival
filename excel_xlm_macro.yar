rule Excel_XLM_Macro_Obfuscation {
    meta:
        description = "Detects legacy Excel 4.0 (XLM) macros using dangerous execution functions"
        author = "User"
        severity = "high"
        reference = "Excel 4.0 Macro Obfuscation via FORMULA.FILL"
    
    strings:
        // The specific dangerous functions in XLM
        $func1 = "FORMULA.FILL" ascii wide nocase
        $func2 = "EXEC" ascii wide nocase
        $func3 = "REGISTER" ascii wide nocase
        $func4 = "HALT" ascii wide nocase
        
        // The auto-execution entry point for XLM
        $auto = "Auto_Open" ascii wide nocase
        
        // Common string obfuscation pattern in XLM (Char function)
        $char_obfu = "CHAR(" ascii wide nocase

    condition:
        // 1. Auto_Open + Dangerous Function
        ($auto and 1 of ($func*))
        
        // 2. Auto_Open + Obfuscation (Using CHAR to hide commands)
        // FIX: This line now references $char_obfu, solving the error
        or ($auto and $char_obfu)

        // 3. Explicit highly malicious function alone (FORMULA.FILL)
        or $func1
}
