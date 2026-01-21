"""Unit tests for Azure Linux OVAL parser"""
import unittest
from pathlib import Path

from azurelinux_osv.oval import OVALParser, OVALDefinition


class TestOVALParser(unittest.TestCase):
    """Tests for the OVALParser class"""

    @classmethod
    def setUpClass(cls):
        """Load test data"""
        test_file = Path(__file__).parent.parent / 'testdata' / 'OVAL' / 'sample-azurelinux-3.0.xml'
        with open(test_file, 'r', encoding='utf-8') as f:
            cls.oval_content = f.read()
        cls.parser = OVALParser(cls.oval_content)

    def test_parse_document_metadata(self):
        """Test parsing of document generator metadata"""
        doc = self.parser.get_document()
        self.assertEqual(doc.product_name, 'Azure Linux OVAL Definition Generator')
        self.assertEqual(doc.product_version, '19')
        self.assertEqual(doc.schema_version, '5.11')
        self.assertIn('2025-01-15', doc.timestamp)

    def test_parse_definitions_count(self):
        """Test that all definitions are parsed"""
        definitions = self.parser.get_definitions()
        self.assertEqual(len(definitions), 2)

    def test_parse_first_definition(self):
        """Test parsing of the first vulnerability definition"""
        definitions = self.parser.get_definitions()
        defn = definitions[0]

        self.assertEqual(defn.cve_id, 'CVE-2024-12345')
        self.assertEqual(defn.package_name, 'libfoo')
        self.assertEqual(defn.severity, 'High')
        self.assertTrue(defn.patchable)
        self.assertEqual(defn.advisory_id, '47256')
        self.assertEqual(defn.platform, 'Azure Linux 3.0')
        self.assertEqual(defn.fixed_version, '0:1.2.3-1.azl3')
        self.assertIn('buffer overflow', defn.description)

    def test_parse_second_definition(self):
        """Test parsing of the second vulnerability definition"""
        definitions = self.parser.get_definitions()
        defn = definitions[1]

        self.assertEqual(defn.cve_id, 'CVE-2024-67890')
        self.assertEqual(defn.package_name, 'libbar')
        self.assertEqual(defn.severity, 'Critical')
        self.assertFalse(defn.patchable)
        self.assertEqual(defn.advisory_id, '47257')
        self.assertEqual(defn.fixed_version, '0:2.0.0-5.azl3')

    def test_cve_url_parsing(self):
        """Test that CVE URLs are correctly extracted"""
        definitions = self.parser.get_definitions()
        defn = definitions[0]
        self.assertEqual(
            defn.cve_url,
            'https://nvd.nist.gov/vuln/detail/CVE-2024-12345'
        )


class TestOVALParserEdgeCases(unittest.TestCase):
    """Tests for edge cases in OVAL parsing"""

    def test_minimal_oval_document(self):
        """Test parsing a minimal OVAL document"""
        minimal_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <oval:product_name>Test</oval:product_name>
    <oval:product_version>1</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2025-01-01T00:00:00Z</oval:timestamp>
  </generator>
  <definitions></definitions>
  <tests></tests>
  <objects></objects>
  <states></states>
</oval_definitions>'''
        parser = OVALParser(minimal_xml)
        self.assertEqual(len(parser.get_definitions()), 0)

    def test_evr_format_variations(self):
        """Test handling of different EVR format variations"""
        # This tests the parser's ability to extract EVR from state elements
        oval_with_evr = '''<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <oval:product_name>Test</oval:product_name>
    <oval:product_version>1</oval:product_version>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>2025-01-01T00:00:00Z</oval:timestamp>
  </generator>
  <definitions>
    <definition class="vulnerability" id="oval:test:def:1" version="1">
      <metadata>
        <title>CVE-2024-99999 affecting package testpkg for versions less than 1.0.0</title>
        <affected family="unix">
          <platform>Azure Linux 3.0</platform>
        </affected>
        <reference ref_id="CVE-2024-99999" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2024-99999" source="CVE"/>
        <patchable>true</patchable>
        <severity>Medium</severity>
        <description>Test vulnerability</description>
      </metadata>
      <criteria>
        <criterion test_ref="oval:test:tst:1"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:rpminfo_test id="oval:test:tst:1" version="1" check="at least one">
      <linux-def:object object_ref="oval:test:obj:1"/>
      <linux-def:state state_ref="oval:test:ste:1"/>
    </linux-def:rpminfo_test>
  </tests>
  <objects>
    <linux-def:rpminfo_object id="oval:test:obj:1" version="1">
      <linux-def:name>testpkg</linux-def:name>
    </linux-def:rpminfo_object>
  </objects>
  <states>
    <linux-def:rpminfo_state id="oval:test:ste:1" version="1">
      <linux-def:evr datatype="evr_string" operation="less than">1:2.3.4-5.azl3</linux-def:evr>
    </linux-def:rpminfo_state>
  </states>
</oval_definitions>'''
        parser = OVALParser(oval_with_evr)
        definitions = parser.get_definitions()
        self.assertEqual(len(definitions), 1)
        self.assertEqual(definitions[0].fixed_version, '1:2.3.4-5.azl3')


if __name__ == '__main__':
    unittest.main()
