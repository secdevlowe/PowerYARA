# PowerYARA
Automatically Generate YARA Signatures from 01 files using PowerShell.

Overview

This is a PowerShell script that automates the process of generating YARA signatures from a given binary file. It extracts key features like strings, byte patterns, and imports, then formats them into a YARA rule to aid in malware detection and reverse engineering.

Features

✅ Extracts unique strings from binaries for signature creation.
✅ Identifies common API imports and suspicious function calls.
✅ Generates hex patterns from the binary for more precise detection.
✅ Outputs a formatted YARA rule with customizable metadata.
✅ Supports PE files, DLLs, and other executables.

Installation

Prerequisites

Windows OS (PowerShell 5.1+ recommended)

PE file analysis tools (optional: Get-PEHeaders module)


Clone the Repository

git clone https://github.com/yourusername/AutoYaraGen.git
cd AutoYaraGen

Usage

Basic YARA Rule Generation

Run the script and provide a binary file:

.\AutoYaraGen.ps1 -FilePath "C:\malware\sample.exe" -RuleName "Malware_Sample"

Example Output (Generated YARA Rule)

rule Malware_Sample
{
    meta:
        author = "YourName"
        date = "2025-02-18"
        description = "Auto-generated YARA rule for sample.exe"
        hash = "d41d8cd98f00b204e9800998ecf8427e"
        
    strings:
        $s1 = "malicious_function" fullword ascii
        $s2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii

    condition:
        any of them
}

Advanced Usage

Extract API Imports & Generate More Detailed Rules

.\AutoYaraGen.ps1 -FilePath "C:\malware\sample.exe" -IncludeImports

Generate Rule and Save Output to File

.\AutoYaraGen.ps1 -FilePath "C:\malware\sample.exe" -OutputPath "C:\yara_rules\sample_rule.yar"
