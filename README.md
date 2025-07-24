# DefenderRuleParser
Tool designed to analyze and extract detection rules from Microsoft Defender binary signature files.

# Description
DefenderRuleParser is a reverse engineering tool designed to analyze and extract detection rules from Microsoft Defender binary signature files. This project aims to document and decode the internal structure of Defender signature database and provide insight into how various signature types operate.

# Features
Parses .bin signature files from Defender signature database (You can obtain them with the DefenderRules tool)

Extracts threat information, including IDs, names, and associated signature types

Supports a wide and growing range of signature formats

Outputs structured data in JSON format for further analysis or conversion

A user-friendly HTML visualization of all parsed rules

Automatically generates YARA files for each parsed Defender rule (in testing)

Detects string-based, hash-based, registry, filepath, Lua, and other rule types

Provides readable hex dumps and decoded patterns where applicable

Designed to assist malware analysts and researchers

# Requirements
.NET Core or .NET Framework (compatible with C# 8.0+)

Windows Defender installed

PowerShell access (for retrieving threat catalog via Get-MpThreatCatalog)


# Usage
DefenderRuleParser <file.bin>
DefenderRuleParser <folderPath> [--recursive] [--skip-existing]

Use RunMe3.bat to automate the parsing of all of .bin files

# Arguments
file.bin: A single Defender binary signature file

folderPath: A folder containing multiple .bin files

--recursive: (Optional) Recursively scan subfolders

--skip-existing: (Optional) Skip .bin files that already have an associated .json output

# Output
Each parsed .bin file will generate a .json file in the same directory, containing structured information about detected threats, including their offset, signature type, and any parsed patterns.

# Extensibility
The tool is modular. New signature types can be supported by implementing a corresponding parser class and registering it in the signature dispatcher. This design allows continuous expansion as more undocumented Defender rules are discovered.

# Research Focus
This project is part of an ongoing effort to understand the detection logic used by Microsoft Defender. It is intended for educational, research, and interoperability purposes. The tool does not modify or interfere with Defender operation.


# Disclaimer
The project is still in the testing phase.

This tool is intended for educational and security analysis purposes only.
Improper use may violate Microsoft's license agreements. Use responsibly and only on systems you own or are authorized to analyze.

# Author
Project: Andrea Cristaldi <a href="https://www.linkedin.com/in/andreacristaldi/" target="blank_">Linkedin</a>, <a href="https://www.cybersec4.com" target="blank_">Cybersec4</a>

# License
This project is licensed under the MIT License.