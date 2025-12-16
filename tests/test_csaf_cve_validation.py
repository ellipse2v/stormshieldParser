# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/env python3
"""
Test to validate the structure of generated CSAF CVE documents.
This test checks that the CSAF CVE documents comply with the CSAF 2.0 schema.
"""

import json
import os
import sys
from pathlib import Path

# Add the parent path to import the main module
sys.path.insert(0, str(Path(__file__).parent.parent))

from stormshield_parser import StormshieldMultiFormatGenerator
import configparser

def test_csaf_cve_validation():
    """Validation test for generated CSAF CVE documents."""
    
    # Load configuration
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    # Create a generator instance
    generator = StormshieldMultiFormatGenerator(config=config, base_dir="test_cvss_output")
    
    # Load a test advisory
    test_advisory_file = Path("test_cvss_output/csaf_cve/cve_2014_6271-2014-001.json")
    
    if not test_advisory_file.exists():
        assert False, f"Test file not found: {test_advisory_file}"
    
    # Load the CSAF CVE document
    with open(test_advisory_file, 'r', encoding='utf-8') as f:
        csaf_doc = json.load(f)
    
    # Basic structure validation
    print("Validating CSAF CVE structure...")
    
    # 1. Check for mandatory fields
    required_fields = [
        "document",
        "product_tree", 
        "vulnerabilities"
    ]
    
    for field in required_fields:
        assert field in csaf_doc, f"❌ Missing mandatory field: {field}"
        print(f"✓ Field {field} present")
    
    # 2. Check document structure
    document = csaf_doc["document"]
    required_doc_fields = [
        "category",
        "csaf_version", 
        "title",
        "publisher",
        "tracking"
    ]
    
    for field in required_doc_fields:
        assert field in document, f"❌ Missing document field: document.{field}"
        print(f"✓ Field document.{field} present")
    
    # 3. Check CSAF category and version
    assert document["category"] == "csaf_security_advisory", f"❌ Incorrect category: {document['category']}"
    print(f"✓ Correct category: {document['category']}")
    
    assert document["csaf_version"] == "2.0", f"❌ Incorrect CSAF version: {document['csaf_version']}"
    print(f"✓ Correct CSAF version: {document['csaf_version']}")
    
    # 4. Check publisher structure
    publisher = document["publisher"]
    assert publisher["category"] == "vendor", f"❌ Incorrect publisher category: {publisher['category']}"
    print(f"✓ Correct publisher category: {publisher['category']}")
    
    assert publisher["name"] == "Stormshield", f"❌ Incorrect publisher name: {publisher['name']}"
    print(f"✓ Correct publisher name: {publisher['name']}")
    
    # 5. Check tracking structure
    tracking = document["tracking"]
    required_tracking_fields = [
        "id",
        "status",
        "version",
        "revision_history",
        "initial_release_date",
        "current_release_date"
    ]
    
    for field in required_tracking_fields:
        assert field in tracking, f"❌ Missing tracking field: tracking.{field}"
        print(f"✓ Field tracking.{field} present")
    
    # 6. Check vulnerabilities
    vulnerabilities = csaf_doc["vulnerabilities"]
    assert vulnerabilities, "❌ No vulnerabilities found"
    print(f"✓ {len(vulnerabilities)} vulnerability(ies) found")
    
    for vuln in vulnerabilities:
        assert "cve" in vuln, "❌ Missing CVE field in a vulnerability"
        print(f"✓ CVE present: {vuln['cve']}")
        
        assert "product_status" in vuln, f"❌ Missing product_status field for CVE {vuln['cve']}"
        print(f"✓ Product status present for CVE {vuln['cve']}")
        
        # Check for CVSS scores if available
        if "scores" in vuln:
            scores = vuln["scores"]
            for score in scores:
                if "cvss_v3" in score:
                    cvss = score["cvss_v3"]
                    assert "version" in cvss, f"❌ Incomplete CVSS score for CVE {vuln['cve']}"
                    
                    has_base_score = "baseScore" in cvss
                    has_base_severity = "baseSeverity" in cvss
                    
                    if has_base_score and has_base_severity:
                        print(f"✓ Full CVSS v3 score for CVE {vuln['cve']}: {cvss['baseScore']} ({cvss['baseSeverity']})")
                    elif has_base_score:
                        print(f"✓ Partial CVSS v3 score for CVE {vuln['cve']}: {cvss['baseScore']} (severity not available)")
                    else:
                        print(f"✓ CVSS v3 structure present for CVE {vuln['cve']} (score not available)")
                if "cvss_v2" in score:
                    cvss = score["cvss_v2"]
                    assert "version" in cvss, f"❌ Incomplete CVSS score for CVE {vuln['cve']}"
                    print(f"✓ CVSS v2 score structure present for CVE {vuln['cve']}")

    
    # 7. Check product tree
    product_tree = csaf_doc["product_tree"]
    assert "branches" in product_tree, "❌ Missing branches field in product_tree"
    print(f"✓ Product tree with {len(product_tree['branches'])} branch(es)")
    
    print("\n✅ All CSAF CVE validation tests passed!")

def test_csaf_cve_content():
    """Test specific content of CSAF CVE documents."""
    
    # Load the test CSAF CVE document
    test_advisory_file = Path("test_cvss_output/csaf_cve/cve_2014_6271-2014-001.json")
    
    if not test_advisory_file.exists():
        assert False, f"Test file not found: {test_advisory_file}"
    
    with open(test_advisory_file, 'r', encoding='utf-8') as f:
        csaf_doc = json.load(f)
    
    print("\nTesting specific CSAF CVE content...")
    
    # Check the specific CVE
    vulnerabilities = csaf_doc["vulnerabilities"]
    assert vulnerabilities, "❌ No CVE found in document"
    
    cve = vulnerabilities[0]["cve"]
    assert cve == "CVE-2014-6271", f"❌ Incorrect CVE: {cve}"
    print(f"✓ Correct CVE: {cve}")
    
    # Check the CVSS score
    if "scores" in vulnerabilities[0]:
        score_block = vulnerabilities[0]["scores"][0]
        assert "cvss_v2" in score_block, "❌ cvss_v2 block not found"
        cvss = score_block["cvss_v2"]
        # Check if base fields are present (they can be optional)
        if "baseScore" in cvss:
            # Check that the score is valid (between 0 and 10)
            assert 0 <= cvss["baseScore"] <= 10, f"❌ Invalid CVSS score: {cvss['baseScore']}"
            print(f"✓ Valid CVSS score: {cvss['baseScore']}")
        else:
            print("⚠️  Base CVSS score not available (optional)")
        
        print("✓ CVSS scores structure present")
    
    # Check the tracking ID
    tracking_id = csaf_doc["document"]["tracking"]["id"]
    assert "cve-2014-6271" in tracking_id, f"❌ Incorrect tracking ID: {tracking_id}"
    print(f"✓ Correct tracking ID: {tracking_id}")
    
    print("\n✅ All CSAF CVE content tests passed!")

if __name__ == "__main__":
    print("=" * 60)
    print("CSAF CVE VALIDATION TEST")
    print("=" * 60)
    
    # Execute tests
    try:
        test_csaf_cve_validation()
        test_csaf_cve_content()
        print("\n🎉 All tests passed!")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n{e}")
        print("\n❌ Some tests failed!")
        sys.exit(1)