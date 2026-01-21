"""Module for converting Azure Linux OVAL data to OSV format"""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional

from .oval import OVALDefinition, OVALDocument, OVALParser

# Update this if verified against a later version
SCHEMA_VERSION = "1.6.0"
# This assumes the datetime being formatted is in UTC
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Platform to ecosystem mapping (base platform names without version)
PLATFORM_ECOSYSTEM_MAP = {
    'Azure Linux': 'Azure Linux',
    'CBL-Mariner': 'Azure Linux',
}

# EVR suffix to version mapping
EVR_SUFFIX_VERSION_MAP = {
    '.azl3': ':3',
    '.cm2': ':2',
    '.cm1': ':1',
}

# Severity mapping (OVAL severity to a descriptive format)
SEVERITY_MAP = {
    'Critical': 'CRITICAL',
    'High': 'HIGH',
    'Medium': 'MEDIUM',
    'Low': 'LOW',
}


class OSVEncoder(json.JSONEncoder):
    """Encodes OSV objects into JSON format"""

    def default(self, o):
        if isinstance(o, Event):
            return o.encode_json()
        if hasattr(o, '__dict__'):
            # Filter out None values and empty lists
            return {k: v for k, v in o.__dict__.items()
                    if v is not None and v != [] and v != {}}
        return super().default(o)


@dataclass
class Event:
    """
    Class to hold event information for a Range.
    Azure Linux OVAL assumes all versions before the fixed version are affected.
    """
    event_type: Literal["introduced", "fixed"]
    version: str = "0"

    def encode_json(self) -> dict:
        """Custom JSON encoding for event type"""
        return {self.event_type: self.version}


@dataclass
class Range:
    """
    Class to hold range information for a Package.
    Uses ECOSYSTEM type for RPM version comparison.
    """
    type: str = "ECOSYSTEM"
    events: list[Event] = field(default_factory=list)

    def __init__(self, fixed_version: str):
        self.type = "ECOSYSTEM"
        self.events = [Event("introduced", "0"), Event("fixed", fixed_version)]


@dataclass
class Package:
    """Class to hold package data for an Affected entry"""
    name: str
    ecosystem: str
    purl: Optional[str] = None

    def __post_init__(self):
        # Generate PURL if not provided
        if self.purl is None:
            # Determine the correct PURL namespace based on ecosystem
            if 'Azure Linux' in self.ecosystem or 'CBL-Mariner' in self.ecosystem:
                self.purl = f"pkg:rpm/microsoft/{self.name}"


@dataclass
class Affected:
    """Class to hold affected data for a vulnerability"""
    package: Package
    ranges: list[Range]


@dataclass
class Reference:
    """Class to hold reference data"""
    type: str
    url: str


class OSV:
    """Class to convert OVAL definition to OSV format"""

    def __init__(
        self,
        definition: OVALDefinition,
        platform: str,
        modified: str,
        published: Optional[str] = None
    ):
        self.schema_version = SCHEMA_VERSION

        # Generate OSV ID from advisory_id or create from CVE + package
        if definition.advisory_id:
            # Use advisory ID if available, converting to AZL prefix
            self.id = self._generate_id(definition)
        else:
            # Fallback: generate from CVE and package
            self.id = self._generate_id(definition)

        # CVE is the primary alias
        self.aliases = [definition.cve_id] if definition.cve_id else []

        # Timestamps
        self.published = published or modified
        self.modified = modified

        # Summary from the OVAL title or generate one
        self.summary = self._generate_summary(definition)

        # Details from the description
        self.details = definition.description if definition.description else None

        # Affected packages
        self.affected = self._build_affected(definition, platform)

        # References
        self.references = self._build_references(definition)

        # Database-specific metadata
        self.database_specific = {
            'severity': definition.severity,
            'patchable': definition.patchable,
        }
        if definition.advisory_id:
            self.database_specific['advisory_id'] = definition.advisory_id

    def _generate_id(self, definition: OVALDefinition) -> str:
        """Generate OSV ID from the definition"""
        # Extract numeric part from advisory_id if present
        if definition.advisory_id:
            # advisory_id might be like "12345" or some other format
            return f"AZL-{definition.advisory_id}"

        # Fallback: use CVE ID with package hash for uniqueness
        cve_part = definition.cve_id.replace('CVE-', '') if definition.cve_id else 'UNKNOWN'
        # Use a simple numeric ID based on package name hash
        pkg_hash = abs(hash(definition.package_name)) % 10000
        return f"AZL-{cve_part}-{pkg_hash:04d}"

    def _generate_summary(self, definition: OVALDefinition) -> str:
        """Generate a human-readable summary"""
        if definition.cve_id and definition.package_name:
            return f"{definition.cve_id} - {definition.package_name}"
        return definition.title

    def _build_affected(
        self,
        definition: OVALDefinition,
        platform: str
    ) -> list[Affected]:
        """Build affected package list"""
        # Get base ecosystem from platform
        base_ecosystem = PLATFORM_ECOSYSTEM_MAP.get(platform, 'Azure Linux')

        # Parse the fixed version from EVR format
        fixed_version = self._parse_evr(definition.fixed_version)

        # Extract version suffix from the EVR to determine distro version
        version_suffix = self._get_version_suffix(definition.fixed_version)
        ecosystem = f"{base_ecosystem}{version_suffix}"

        package = Package(
            name=definition.package_name,
            ecosystem=ecosystem
        )
        ranges = [Range(fixed_version)]

        return [Affected(package, ranges)]

    def _get_version_suffix(self, evr: str) -> str:
        """
        Extract the distro version suffix from the EVR string.
        e.g., "0:1.2.3-1.azl3" -> ":3"
              "0:1.2.3-1.cm2" -> ":2"
        """
        if not evr:
            return ''

        for suffix, version in EVR_SUFFIX_VERSION_MAP.items():
            if suffix in evr:
                return version

        return ''

    def _parse_evr(self, evr: str) -> str:
        """
        Parse EVR (epoch:version-release) format.
        Returns the version in a format suitable for OSV.
        e.g., "0:1.10.6-1.azl3" -> "1.10.6-1.azl3"
        """
        if not evr:
            return "0"

        # EVR format: epoch:version-release
        # We want to preserve the full version for RPM ecosystem comparison
        if ':' in evr:
            epoch, version_release = evr.split(':', 1)
            # Include epoch only if it's not 0
            if epoch and epoch != '0':
                return evr
            return version_release
        return evr

    def _build_references(self, definition: OVALDefinition) -> list[dict]:
        """Build reference list"""
        refs = []

        # Add NVD/CVE reference
        if definition.cve_url:
            refs.append({'type': 'ADVISORY', 'url': definition.cve_url})

        # Add Azure Linux specific reference if we can construct one
        if definition.cve_id:
            # NVD link as backup
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{definition.cve_id}"
            if not any(r['url'] == nvd_url for r in refs):
                refs.append({'type': 'ADVISORY', 'url': nvd_url})

        return refs


class AzureLinuxConverter:
    """
    Class which converts Azure Linux OVAL XML to OSV JSON format.
    Can process individual definitions or entire OVAL files.
    """

    def __init__(self, validate_schema: bool = False):
        """
        Initialize converter.

        Args:
            validate_schema: If True, validate output against OSV schema.
                           Requires jsonschema and network access.
        """
        self.validate_schema = validate_schema
        self.osv_schema = None

        if validate_schema:
            self._load_schema()

    def _load_schema(self):
        """Load OSV schema for validation"""
        try:
            import requests
            from jsonschema import validate
            schema_url = (
                f"https://raw.githubusercontent.com/ossf/osv-schema/v{SCHEMA_VERSION}"
                "/validation/schema.json"
            )
            response = requests.get(schema_url, timeout=60)
            self.osv_schema = response.json()
        except Exception as e:
            print(f"Warning: Could not load OSV schema for validation: {e}")
            self.validate_schema = False

    def convert_file(
        self,
        oval_content: str,
        modified: Optional[str] = None
    ) -> list[tuple[str, str]]:
        """
        Convert an OVAL XML file to multiple OSV JSON records.

        Args:
            oval_content: The OVAL XML content as a string
            modified: Modified timestamp (defaults to current time)

        Returns:
            List of tuples (osv_id, osv_json_string)
        """
        if modified is None:
            modified = datetime.now(timezone.utc).strftime(DATE_FORMAT)

        parser = OVALParser(oval_content)
        document = parser.get_document()

        results = []
        for definition in parser.get_definitions():
            try:
                osv_id, osv_json = self.convert_definition(
                    definition,
                    document.timestamp,
                    modified
                )
                results.append((osv_id, osv_json))
            except Exception as e:
                print(f"Warning: Failed to convert {definition.cve_id}: {e}")

        return results

    def convert_definition(
        self,
        definition: OVALDefinition,
        published: Optional[str] = None,
        modified: Optional[str] = None
    ) -> tuple[str, str]:
        """
        Convert a single OVAL definition to OSV format.

        Args:
            definition: Parsed OVAL definition
            published: Published timestamp
            modified: Modified timestamp

        Returns:
            Tuple of (osv_id, osv_json_string)
        """
        if modified is None:
            modified = datetime.now(timezone.utc).strftime(DATE_FORMAT)

        # Normalize timestamps
        if published:
            published = self._normalize_timestamp(published)
        modified = self._normalize_timestamp(modified)

        osv = OSV(
            definition=definition,
            platform=definition.platform,
            modified=modified,
            published=published
        )

        # Convert to JSON
        osv_content = json.dumps(osv, cls=OSVEncoder, indent=2)

        # Validate if enabled
        if self.validate_schema and self.osv_schema:
            from jsonschema import validate
            osv_data = json.loads(osv_content)
            validate(osv_data, schema=self.osv_schema)

        return osv.id, osv_content

    def _normalize_timestamp(self, timestamp: str) -> str:
        """
        Normalize timestamp to OSV format (RFC 3339).
        Handles various input formats from OVAL.
        """
        # If already in correct format, return as-is
        if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', timestamp):
            return timestamp

        # Try parsing ISO 8601 with microseconds
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime(DATE_FORMAT)
        except ValueError:
            pass

        # Try other common formats
        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d']:
            try:
                dt = datetime.strptime(timestamp, fmt)
                return dt.strftime(DATE_FORMAT)
            except ValueError:
                continue

        # If all else fails, use current time
        return datetime.utcnow().strftime(DATE_FORMAT)
