#!/usr/bin/env python3
"""
Convert Azure Linux OVAL vulnerability data to OSV format.

This tool processes OVAL XML files from the Azure Linux Vulnerability Data
repository and converts them to individual OSV JSON files.

Usage:
    python convert_azurelinux.py azurelinux-3.0-oval.xml -o output/

The tool will create one OSV JSON file per vulnerability definition in the
specified output directory.
"""
import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from azurelinux_osv.osv import DATE_FORMAT, AzureLinuxConverter


def main():
    """
    Convert Azure Linux OVAL file(s) to OSV format.
    """
    parser = argparse.ArgumentParser(
        description='Azure Linux OVAL to OSV Converter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Convert a single OVAL file
    python convert_azurelinux.py azurelinux-3.0-oval.xml -o osv/

    # Convert with schema validation
    python convert_azurelinux.py azurelinux-3.0-oval.xml -o osv/ --validate

    # Convert multiple files
    python convert_azurelinux.py *.xml -o osv/
"""
    )

    parser.add_argument(
        'oval_files',
        metavar='FILE',
        nargs='+',
        help='OVAL XML file(s) to process'
    )
    parser.add_argument(
        '-o', '--output-dir',
        dest='output_dir',
        default='osv',
        help='Output directory for OSV files (default: osv/)'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate output against OSV schema (requires network)'
    )
    parser.add_argument(
        '--modified',
        help='Override modified timestamp (ISO 8601 format)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Create output directory
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize converter
    converter = AzureLinuxConverter(validate_schema=args.validate)

    # Process modified timestamp
    modified = args.modified
    if modified is None:
        modified = datetime.now(timezone.utc).strftime(DATE_FORMAT)

    total_converted = 0
    total_errors = 0

    for oval_file in args.oval_files:
        if args.verbose:
            print(f"Processing: {oval_file}")

        try:
            with open(oval_file, 'r', encoding='utf-8') as f:
                oval_content = f.read()

            results = converter.convert_file(oval_content, modified)

            for osv_id, osv_json in results:
                output_file = output_path / f"{osv_id}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(osv_json)
                    f.write('\n')

                if args.verbose:
                    print(f"  Created: {output_file}")

                total_converted += 1

        except Exception as e:
            print(f"Error processing {oval_file}: {e}", file=sys.stderr)
            total_errors += 1

    print(f"Converted {total_converted} definitions to OSV format")
    if total_errors > 0:
        print(f"Encountered {total_errors} errors", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
