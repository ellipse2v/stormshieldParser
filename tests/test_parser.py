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
import pytest
from pathlib import Path
import configparser
from unittest.mock import Mock

from stormshield_parser import StormshieldMultiFormatGenerator

@pytest.fixture
def generator():
    """Returns a configured StormshieldMultiFormatGenerator instance."""
    config = configparser.ConfigParser()
    config.read('config.ini')
    return StormshieldMultiFormatGenerator(config=config, base_dir='test_output')

@pytest.fixture
def advisory_html():
    """Returns the HTML content of a sample advisory page."""
    fixture_path = Path(__file__).parent / "fixtures/advisory_2025-006.html"
    with open(fixture_path, 'r', encoding='utf-8') as f:
        return f.read()

def test_parse_advisory_page(generator, advisory_html, mocker):
    """
    Tests the parsing of a single advisory HTML page from a local fixture.
    """
    # Mock the HTTP response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = advisory_html.encode('utf-8')
    mocker.patch.object(generator.session, 'get', return_value=mock_response)

    advisory_id = '2025-006'
    advisory_url = f"https://advisories.stormshield.eu/{advisory_id}"
    products = ["Stormshield Network VPN Client"]

    # Call the method to test
    advisory_data = generator.parse_advisory_page(advisory_url, advisory_id, products)

    # Assertions
    assert advisory_data is not None
    assert advisory_data['id'] == '2025-006'
    assert advisory_data['title'] == 'Incorrect validation of OCSP certificates'
    assert advisory_data['cves'] == ['CVE-2025-11955']
    assert advisory_data['cvss_score'] == 8.1
    assert advisory_data['severity'] == 'high'
    assert 'Stormshield Network VPN Client Exclusive 7.5.109' in advisory_data['description']
    assert advisory_data['date'] == '2025-11-27T12:00:00+01:00'
