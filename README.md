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

## Output

Parsed files are saved in the same directory as the original, with `_parsed` appended to the filename

Example: `HitmanPro.log` &rarr; `HitmanPro_parsed.log` or `HitmanPro.txt` &rarr; `HitmanPro_parsed.txt`
