"""Unit tests for Azure Linux OSV converter"""
import json
import unittest
from pathlib import Path

from azurelinux_osv.oval import OVALParser
from azurelinux_osv.osv import AzureLinuxConverter, OSV, DATE_FORMAT


class TestOSVConversion(unittest.TestCase):
    """Tests for OSV conversion"""

    @classmethod
    def setUpClass(cls):
        """Load test data and convert"""
        test_file = Path(__file__).parent.parent / 'testdata' / 'OVAL' / 'sample-azurelinux-3.0.xml'
        with open(test_file, 'r', encoding='utf-8') as f:
            cls.oval_content = f.read()

        cls.converter = AzureLinuxConverter(validate_schema=False)
        cls.results = cls.converter.convert_file(
            cls.oval_content,
            modified='2025-01-20T12:00:00Z'
        )

    def test_conversion_count(self):
        """Test that all definitions are converted"""
        self.assertEqual(len(self.results), 2)

    def test_osv_id_format(self):
        """Test that OSV IDs follow the expected format"""
        for osv_id, _ in self.results:
            self.assertTrue(osv_id.startswith('AZL-'))

    def test_osv_json_valid(self):
        """Test that output is valid JSON"""
        for osv_id, osv_json in self.results:
            try:
                data = json.loads(osv_json)
                self.assertIsInstance(data, dict)
            except json.JSONDecodeError:
                self.fail(f"Invalid JSON for {osv_id}")

    def test_osv_required_fields(self):
        """Test that required OSV fields are present"""
        for osv_id, osv_json in self.results:
            data = json.loads(osv_json)
            self.assertIn('schema_version', data)
            self.assertIn('id', data)
            self.assertIn('modified', data)

    def test_osv_affected_structure(self):
        """Test the affected package structure"""
        _, osv_json = self.results[0]
        data = json.loads(osv_json)

        self.assertIn('affected', data)
        self.assertEqual(len(data['affected']), 1)

        affected = data['affected'][0]
        self.assertIn('package', affected)
        self.assertIn('ranges', affected)

        package = affected['package']
        self.assertEqual(package['name'], 'libfoo')
        self.assertEqual(package['ecosystem'], 'Azure Linux:3')
        self.assertIn('purl', package)

    def test_osv_ranges_structure(self):
        """Test the ranges structure"""
        _, osv_json = self.results[0]
        data = json.loads(osv_json)

        ranges = data['affected'][0]['ranges']
        self.assertEqual(len(ranges), 1)

        range_entry = ranges[0]
        self.assertEqual(range_entry['type'], 'ECOSYSTEM')
        self.assertEqual(len(range_entry['events']), 2)

        events = range_entry['events']
        self.assertEqual(events[0], {'introduced': '0'})
        self.assertEqual(events[1], {'fixed': '1.2.3-1.azl3'})

    def test_osv_aliases(self):
        """Test that CVE is included in aliases"""
        _, osv_json = self.results[0]
        data = json.loads(osv_json)

        self.assertIn('aliases', data)
        self.assertIn('CVE-2024-12345', data['aliases'])

    def test_osv_references(self):
        """Test reference structure"""
        _, osv_json = self.results[0]
        data = json.loads(osv_json)

        self.assertIn('references', data)
        refs = data['references']
        self.assertGreater(len(refs), 0)

        # Each reference should have type and url
        for ref in refs:
            self.assertIn('type', ref)
            self.assertIn('url', ref)

    def test_osv_database_specific(self):
        """Test database_specific metadata"""
        _, osv_json = self.results[0]
        data = json.loads(osv_json)

        self.assertIn('database_specific', data)
        db_specific = data['database_specific']
        self.assertEqual(db_specific['severity'], 'High')
        self.assertTrue(db_specific['patchable'])


class TestEVRParsing(unittest.TestCase):
    """Tests for EVR version string parsing"""

    def test_evr_with_zero_epoch(self):
        """Test EVR with epoch 0 is stripped"""
        converter = AzureLinuxConverter(validate_schema=False)
        osv = OSV.__new__(OSV)
        result = osv._parse_evr('0:1.2.3-1.azl3')
        self.assertEqual(result, '1.2.3-1.azl3')

    def test_evr_with_nonzero_epoch(self):
        """Test EVR with non-zero epoch is preserved"""
        converter = AzureLinuxConverter(validate_schema=False)
        osv = OSV.__new__(OSV)
        result = osv._parse_evr('1:2.3.4-5.azl3')
        self.assertEqual(result, '1:2.3.4-5.azl3')

    def test_evr_without_epoch(self):
        """Test EVR without epoch"""
        converter = AzureLinuxConverter(validate_schema=False)
        osv = OSV.__new__(OSV)
        result = osv._parse_evr('1.2.3-1')
        self.assertEqual(result, '1.2.3-1')

    def test_evr_empty(self):
        """Test empty EVR returns 0"""
        converter = AzureLinuxConverter(validate_schema=False)
        osv = OSV.__new__(OSV)
        result = osv._parse_evr('')
        self.assertEqual(result, '0')


class TestTimestampNormalization(unittest.TestCase):
    """Tests for timestamp normalization"""

    def test_already_normalized(self):
        """Test timestamp already in correct format"""
        converter = AzureLinuxConverter(validate_schema=False)
        result = converter._normalize_timestamp('2025-01-15T10:00:00Z')
        self.assertEqual(result, '2025-01-15T10:00:00Z')

    def test_with_microseconds(self):
        """Test timestamp with microseconds"""
        converter = AzureLinuxConverter(validate_schema=False)
        result = converter._normalize_timestamp('2025-01-15T10:00:00.123456Z')
        self.assertEqual(result, '2025-01-15T10:00:00Z')


class TestEcosystemMapping(unittest.TestCase):
    """Tests for ecosystem mapping"""

    def test_azure_linux_3_mapping(self):
        """Test Azure Linux 3.0 ecosystem mapping from EVR suffix"""
        from azurelinux_osv.osv import EVR_SUFFIX_VERSION_MAP
        self.assertEqual(EVR_SUFFIX_VERSION_MAP['.azl3'], ':3')

    def test_cbl_mariner_2_mapping(self):
        """Test CBL-Mariner 2.0 ecosystem mapping from EVR suffix"""
        from azurelinux_osv.osv import EVR_SUFFIX_VERSION_MAP
        self.assertEqual(EVR_SUFFIX_VERSION_MAP['.cm2'], ':2')

    def test_cbl_mariner_1_mapping(self):
        """Test CBL-Mariner 1.0 ecosystem mapping from EVR suffix"""
        from azurelinux_osv.osv import EVR_SUFFIX_VERSION_MAP
        self.assertEqual(EVR_SUFFIX_VERSION_MAP['.cm1'], ':1')


if __name__ == '__main__':
    unittest.main()
