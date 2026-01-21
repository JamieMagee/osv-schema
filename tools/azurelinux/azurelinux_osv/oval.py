"""Module for parsing Azure Linux OVAL XML data"""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


# OVAL XML namespaces
NAMESPACES = {
    'oval': 'http://oval.mitre.org/XMLSchema/oval-common-5',
    'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'linux-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
}


@dataclass
class OVALDefinition:
    """Represents a single OVAL vulnerability definition"""
    definition_id: str
    title: str
    description: str
    cve_id: str
    cve_url: str
    severity: str
    patchable: bool
    advisory_date: str
    advisory_id: str
    platform: str
    package_name: str
    fixed_version: str  # EVR format: epoch:version-release


@dataclass
class OVALDocument:
    """Represents a parsed OVAL document"""
    product_name: str
    product_version: str
    schema_version: str
    timestamp: str
    definitions: list[OVALDefinition] = field(default_factory=list)


class OVALParser:
    """Parser for Azure Linux OVAL XML files"""

    # Pattern to extract package name and version from title
    # e.g., "CVE-2025-11961 affecting package libpcap for versions less than 1.10.6-1"
    TITLE_PATTERN = re.compile(
        r'(CVE-\d{4}-\d+)\s+affecting\s+package\s+(\S+)\s+for\s+versions\s+less\s+than\s+(\S+)'
    )

    def __init__(self, xml_content: str):
        self.root = ET.fromstring(xml_content)
        self.document = self._parse_document()

    def _parse_document(self) -> OVALDocument:
        """Parse the entire OVAL document"""
        # Parse generator metadata
        generator = self.root.find('oval-def:generator', NAMESPACES)
        product_name = self._get_text(generator, 'oval:product_name')
        product_version = self._get_text(generator, 'oval:product_version')
        schema_version = self._get_text(generator, 'oval:schema_version')
        timestamp = self._get_text(generator, 'oval:timestamp')

        doc = OVALDocument(
            product_name=product_name,
            product_version=product_version,
            schema_version=schema_version,
            timestamp=timestamp
        )

        # Build lookup tables for tests, objects, and states
        tests = self._build_tests_lookup()
        objects = self._build_objects_lookup()
        states = self._build_states_lookup()

        # Parse definitions
        definitions_elem = self.root.find('oval-def:definitions', NAMESPACES)
        if definitions_elem is not None:
            for def_elem in definitions_elem.findall('oval-def:definition', NAMESPACES):
                definition = self._parse_definition(def_elem, tests, objects, states)
                if definition:
                    doc.definitions.append(definition)

        return doc

    def _get_text(self, parent: Optional[ET.Element], tag: str, default: str = '') -> str:
        """Get text content of a child element"""
        if parent is None:
            return default
        elem = parent.find(tag, NAMESPACES)
        return elem.text if elem is not None and elem.text else default

    def _build_tests_lookup(self) -> dict[str, str]:
        """Build lookup from test ID to object ID"""
        tests = {}
        tests_elem = self.root.find('oval-def:tests', NAMESPACES)
        if tests_elem is not None:
            for test in tests_elem.findall('linux-def:rpminfo_test', NAMESPACES):
                test_id = test.get('id', '')
                obj_elem = test.find('linux-def:object', NAMESPACES)
                state_elem = test.find('linux-def:state', NAMESPACES)
                if obj_elem is not None and state_elem is not None:
                    tests[test_id] = {
                        'object_ref': obj_elem.get('object_ref', ''),
                        'state_ref': state_elem.get('state_ref', '')
                    }
        return tests

    def _build_objects_lookup(self) -> dict[str, str]:
        """Build lookup from object ID to package name"""
        objects = {}
        objects_elem = self.root.find('oval-def:objects', NAMESPACES)
        if objects_elem is not None:
            for obj in objects_elem.findall('linux-def:rpminfo_object', NAMESPACES):
                obj_id = obj.get('id', '')
                name_elem = obj.find('linux-def:name', NAMESPACES)
                if name_elem is not None and name_elem.text:
                    objects[obj_id] = name_elem.text
        return objects

    def _build_states_lookup(self) -> dict[str, str]:
        """Build lookup from state ID to EVR version string"""
        states = {}
        states_elem = self.root.find('oval-def:states', NAMESPACES)
        if states_elem is not None:
            for state in states_elem.findall('linux-def:rpminfo_state', NAMESPACES):
                state_id = state.get('id', '')
                evr_elem = state.find('linux-def:evr', NAMESPACES)
                if evr_elem is not None and evr_elem.text:
                    states[state_id] = evr_elem.text
        return states

    def _parse_definition(
        self,
        def_elem: ET.Element,
        tests: dict,
        objects: dict,
        states: dict
    ) -> Optional[OVALDefinition]:
        """Parse a single OVAL definition element"""
        def_id = def_elem.get('id', '')
        def_class = def_elem.get('class', '')

        # Only process vulnerability definitions
        if def_class != 'vulnerability':
            return None

        metadata = def_elem.find('oval-def:metadata', NAMESPACES)
        if metadata is None:
            return None

        title = self._get_text(metadata, 'oval-def:title')
        description = self._get_text(metadata, 'oval-def:description')

        # Parse reference (CVE info)
        cve_id = ''
        cve_url = ''
        reference = metadata.find('oval-def:reference', NAMESPACES)
        if reference is not None:
            cve_id = reference.get('ref_id', '')
            cve_url = reference.get('ref_url', '')

        # Parse affected platform
        platform = ''
        affected = metadata.find('oval-def:affected', NAMESPACES)
        if affected is not None:
            platform_elem = affected.find('oval-def:platform', NAMESPACES)
            if platform_elem is not None and platform_elem.text:
                platform = platform_elem.text

        # Parse custom Azure Linux metadata
        patchable_text = self._get_text(metadata, 'oval-def:patchable', 'false')
        patchable = patchable_text.lower() == 'true'
        advisory_date = self._get_text(metadata, 'oval-def:advisory_date')
        advisory_id = self._get_text(metadata, 'oval-def:advisory_id')
        severity = self._get_text(metadata, 'oval-def:severity')

        # Get package name and fixed version from criteria -> test -> object/state
        package_name = ''
        fixed_version = ''

        criteria = def_elem.find('oval-def:criteria', NAMESPACES)
        if criteria is not None:
            criterion = criteria.find('oval-def:criterion', NAMESPACES)
            if criterion is not None:
                test_ref = criterion.get('test_ref', '')
                if test_ref in tests:
                    test_info = tests[test_ref]
                    obj_ref = test_info['object_ref']
                    state_ref = test_info['state_ref']
                    if obj_ref in objects:
                        package_name = objects[obj_ref]
                    if state_ref in states:
                        fixed_version = states[state_ref]

        # Fallback: parse from title if not found in criteria
        if not package_name or not fixed_version:
            match = self.TITLE_PATTERN.match(title)
            if match:
                if not package_name:
                    package_name = match.group(2)
                # Note: version from title doesn't include epoch

        return OVALDefinition(
            definition_id=def_id,
            title=title,
            description=description,
            cve_id=cve_id,
            cve_url=cve_url,
            severity=severity,
            patchable=patchable,
            advisory_date=advisory_date,
            advisory_id=advisory_id,
            platform=platform,
            package_name=package_name,
            fixed_version=fixed_version
        )

    def get_definitions(self) -> list[OVALDefinition]:
        """Return all parsed OVAL definitions"""
        return self.document.definitions

    def get_document(self) -> OVALDocument:
        """Return the parsed OVAL document"""
        return self.document
