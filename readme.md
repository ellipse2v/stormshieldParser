stormshield_output/
├── csaf_vex/              # CSAF VEX format (CISA standard)
│   ├── stormshield-2024-001.json
│   ├── stormshield-2024-002.json
│   └── index.json
│

└── csaf_cve/              # CSAF per CVE (for Dependency-Track)
    ├── cve_2024_1234-2024-001.json
    ├── cve_2024_5678-2024-002.json
    └── index.json
	
	
# Stormshield Security Advisory Parser

This script parses Stormshield security advisories and generates multiple output formats:
- **CSAF VEX** (CISA standard format)
- **CSAF per CVE** (for Dependency-Track)

## Features

### CSAF VEX Format
- One file per Stormshield advisory
- Contains all CVEs for the advisory
- Includes detailed product version information
- Format: `stormshield-YYYY-NNN.json`

### CSAF CVE Format
- One file per CVE per advisory
- Optimized for Dependency-Track import
- Includes product identification helpers (PURL, CPE)
- Format: `cve_YYYY_NNNN-YYYY-NNN.json`

### Enhanced CVSS Support
- Base CVSS scores and vectors
- Temporal CVSS scores and severity
- Environmental CVSS scores and vectors
- Automatic detection and parsing

### Product Identification
- Correct PURL generation for version ranges
- Multiple CPE entries for "and" cases
- Version range parsing and formatting

## Installation

```bash
pip install requests beautifulsoup4
```

## Usage

### Generate ALL formats
```bash
python stormshield_parser.py
```

### Test with 5 advisories
```bash
python stormshield_parser.py --max 5
```

### Custom output directory
```bash
python stormshield_parser.py --output-dir my_exports
```

### Generate indexes only
```bash
python stormshield_parser.py --index-only
```

### Configuration

Edit `config.ini` to customize:
- Proxy settings
- Logging levels
- Performance options
- Output directories

## Output Structure

```
stormshield_output/
├── csaf_vex/              # CSAF VEX documents
│   ├── stormshield-YYYY-NNN.json
│   └── index.json
│
└── csaf_cve/              # CSAF per CVE documents
    ├── cve_YYYY_NNNN-YYYY-NNN.json
    └── index.json
```

## Technical Details

### CVSS Vector Detection
- Base vectors: `CVSS:3.1/AV:N/AC:L/...`
- Temporal vectors: `CVSS:.../T:...`
- Environmental vectors: `CVSS:.../E:...`

### Product Version Handling
- Version ranges: `1.0.0 to 1.1.3` → PURL: `1.0.0-1.1.3`
- Multiple versions: `6.0.15 and 7.1.02` → Separate entries
- CPE wildcards: `*` for version ranges

### Incremental Processing
- Tracks processed advisories in `processed_index.json`
- Only processes new advisories on subsequent runs
- Efficient for scheduled/cron jobs

## Requirements

- Python 3.7+
- requests
- beautifulsoup4

## License

Apache License 2.0