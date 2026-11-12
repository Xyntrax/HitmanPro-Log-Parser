# HitmanPro Log Parser
HitmanPro log parser that simplifies the analysis of large scan logs by extracting and organizing relevant information

## Usage

**Scan current directory:**
```
python hitmanpro_parser.py scan
```
Finds and parses `HitmanPro.txt` and `HitmanPro.log` in the current directory

**Parse a specific file:**
```
python hitmanpro_parser.py targetname.txt
```
```
python hitmanpro_parser.py targetname.log
```

## Forensic Cluster

By default, the **Forensic Cluster** section of each entry is left out of the parsed log. To include it, add the `-fc` argument

**Scan current directory:**
```
python hitmanpro_parser.py -fc scan
```

**Parse a specific file:**
```
python hitmanpro_parser.py -fc targetname.txt
```
```
python hitmanpro_parser.py -fc targetname.log
```

When enabled, each entry that has **Forensic Cluster** gets its own `Forensic Cluster` heading with the cluster paths listed below it, so it's clear which entry each cluster belongs to. Entries without **Forensic Cluster** are shown as a path and SHA-256 only

## Output

Parsed files are saved in the same directory as the original, with `_parsed` appended to the filename

Example: `HitmanPro.log` &rarr; `HitmanPro_parsed.log` or `HitmanPro.txt` &rarr; `HitmanPro_parsed.txt`
