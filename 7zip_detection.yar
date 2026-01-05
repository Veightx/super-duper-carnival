rule SevenZip_Archive_File {
    meta:
        description = "Detects 7-Zip archives by binary magic bytes"
        author = "My Org Security"
        severity = "info" 
    strings:
        // The standard 6-byte header for 7z files: '7z' + 0xBC 0xAF 0x27 0x1C
        $magic = { 37 7A BC AF 27 1C }
    condition:
        // The magic bytes must be at the very start of the file
        $magic at 0
}
