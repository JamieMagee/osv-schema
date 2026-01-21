# Azure Linux OVAL to OSV Converter

This tool converts Azure Linux (formerly CBL-Mariner) OVAL vulnerability data to the OSV (Open Source Vulnerability) format.

## Overview

Azure Linux publishes vulnerability data in OVAL (Open Vulnerability and Assessment Language) format at:
https://github.com/microsoft/AzureLinuxVulnerabilityData

This converter parses the OVAL XML files and generates individual OSV JSON files for each vulnerability.

## Setup

### Using pip

```bash
pip install -e .
```

### Using Pipenv

```bash
pipenv install
pipenv shell
```

## Usage

### Basic Usage

Convert an OVAL file to OSV format:

```bash
python convert_azurelinux.py azurelinux-3.0-oval.xml -o osv/
```

### Options

```
usage: convert_azurelinux.py [-h] [-o OUTPUT_DIR] [--validate] [--modified MODIFIED] [-v] FILE [FILE ...]

Azure Linux OVAL to OSV Converter

positional arguments:
  FILE                  OVAL XML file(s) to process

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output directory for OSV files (default: osv/)
  --validate            Validate output against OSV schema (requires network)
  --modified MODIFIED   Override modified timestamp (ISO 8601 format)
  -v, --verbose         Enable verbose output
```

### Examples

Convert all Azure Linux OVAL files:

```bash
# Clone the vulnerability data
git clone https://github.com/microsoft/AzureLinuxVulnerabilityData.git

# Convert each version
python convert_azurelinux.py AzureLinuxVulnerabilityData/azurelinux-3.0-oval.xml -o osv/azurelinux-3/
python convert_azurelinux.py AzureLinuxVulnerabilityData/cbl-mariner-2.0-oval.xml -o osv/cbl-mariner-2/
python convert_azurelinux.py AzureLinuxVulnerabilityData/cbl-mariner-1.0-oval.xml -o osv/cbl-mariner-1/
```

Convert with schema validation:

```bash
python convert_azurelinux.py azurelinux-3.0-oval.xml -o osv/ --validate
```

## Running Tests

```bash
python -m unittest discover -s azurelinux_osv -p '*_test.py'
```

Or with pipenv:

```bash
pipenv run python -m unittest discover -s azurelinux_osv -p '*_test.py'
```

## Output Format

Each vulnerability definition in the OVAL file is converted to a separate OSV JSON file.

### ID Format

OSV IDs use the `AZL-` prefix followed by the Azure Linux advisory ID:
- `AZL-47256` - Azure Linux advisory 47256

### Ecosystem

The ecosystem is set to `Azure Linux` with a version suffix:
- `Azure Linux:3` - Azure Linux 3.0
- `Azure Linux:2` - CBL-Mariner 2.0 (mapped to Azure Linux)
- `Azure Linux:1` - CBL-Mariner 1.0 (mapped to Azure Linux)

### Package URLs (PURLs)

Packages use the RPM PURL format with Microsoft as the namespace:
- `pkg:rpm/microsoft/libfoo`

### Example OSV Output

```json
{
  "schema_version": "1.6.0",
  "id": "AZL-47256",
  "aliases": ["CVE-2024-12345"],
  "published": "2025-01-15T10:00:00Z",
  "modified": "2025-01-20T12:00:00Z",
  "summary": "CVE-2024-12345 - libfoo",
  "details": "A buffer overflow vulnerability in libfoo...",
  "affected": [
    {
      "package": {
        "name": "libfoo",
        "ecosystem": "Azure Linux:3",
        "purl": "pkg:rpm/microsoft/libfoo"
      },
      "ranges": [
        {
          "type": "ECOSYSTEM",
          "events": [
            {"introduced": "0"},
            {"fixed": "1.2.3-1.azl3"}
          ]
        }
      ]
    }
  ],
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
    }
  ],
  "database_specific": {
    "severity": "High",
    "patchable": true,
    "advisory_id": "47256"
  }
}
```

## How It Works

### OVAL to OSV Mapping

| OVAL Field | OSV Field |
|------------|-----------|
| `advisory_id` | `id` (with AZL- prefix) |
| `reference/@ref_id` (CVE) | `aliases` |
| `generator/timestamp` | `published` |
| Current time | `modified` |
| `title` or CVE + package | `summary` |
| `description` | `details` |
| `platform` | `affected[].package.ecosystem` |
| Object `name` | `affected[].package.name` |
| State `evr` | `affected[].ranges[].events[].fixed` |
| `reference/@ref_url` | `references` |
| `severity`, `patchable` | `database_specific` |

### Version Handling

OVAL uses EVR (Epoch:Version-Release) format for RPM versions. The converter:
- Strips epoch 0 (e.g., `0:1.2.3-1.azl3` → `1.2.3-1.azl3`)
- Preserves non-zero epochs (e.g., `1:2.3.4-5.azl3` remains unchanged)
- All versions before the fixed version are considered affected (`introduced: "0"`)

## Schema Considerations

**Note:** The `Azure Linux` ecosystem is not yet in the official OSV schema. To use this converter in production, you may need to:

1. Request addition of `Azure Linux` to the OSV ecosystem list
2. Use a custom/extended ecosystem name
3. Use the existing `Linux` ecosystem with a suffix

## License

See the repository LICENSE file.
