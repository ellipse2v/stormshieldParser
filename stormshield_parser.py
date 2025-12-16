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
Script to parse all Stormshield advisories and generate:
- CSAF VEX (CISA format)
- CycloneDX SBOM with VEX
- Individual CSAF CVEs for Dependency-Track
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from datetime import datetime
from pathlib import Path
import time
from urllib.parse import urljoin
import uuid
import configparser
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

class StormshieldMultiFormatGenerator:
    def __init__(self, config, base_dir="stormshield_output"):
        self.config = config
        self._setup_logging()

        self.base_url = self.config.get('Network', 'base_url', fallback="https://advisories.stormshield.eu")
        self.base_dir = Path(base_dir)
        
        # Create output directories
        self.csaf_vex_dir = self.base_dir / "csaf_vex"
        self.csaf_cve_dir = self.base_dir / "csaf_cve"
        self.index_file = self.base_dir / "processed_index.json"
        
        for directory in [self.csaf_vex_dir, self.csaf_cve_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; StormshieldParser/1.0)'
        })

        # Proxy configuration
        proxy_http = self.config.get('Network', 'proxy_http', fallback=None)
        proxy_https = self.config.get('Network', 'proxy_https', fallback=None)
        proxies = {}
        if proxy_http:
            proxies['http'] = proxy_http
        if proxy_https:
            proxies['https'] = proxy_https
        if proxies:
            self.session.proxies.update(proxies)
            self.logger.info("Using proxy: %s", proxies)

    def _setup_logging(self):
        """Configure logging for the script."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG) # Capture all levels
        
        # Avoid adding handlers if they already exist
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Console handler
        console_level = self.config.get('Logging', 'log_level_console', fallback='INFO').upper()
        ch = logging.StreamHandler()
        ch.setLevel(console_level)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # File handler
        log_file = self.config.get('Logging', 'log_file', fallback=None)
        if log_file:
            file_level = self.config.get('Logging', 'log_level_file', fallback='DEBUG').upper()
            fh = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            fh.setLevel(file_level)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
    
    def fetch_all_advisories(self):
        """Fetch the complete list of all advisories."""
        self.logger.info("Fetching all advisories from %s...", self.base_url)
        
        try:
            response = self.session.get(self.base_url, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            advisories = []
            script_tag = soup.find('script', string=re.compile(r'var advisories_list = \['))
            
            if script_tag:
                script_content = script_tag.string
                match = re.search(r'var advisories_list = (.*\]);', script_content, re.DOTALL)
                if match:
                    advisories_js = match.group(1)
                    
                    # This is not valid JSON, it's a JS object. We need to convert it.
                    # 1. Add quotes to keys
                    advisories_js = re.sub(r'([{{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', advisories_js)
                    # 2. Replace single quotes with double quotes for string values
                    advisories_js = advisories_js.replace("'", '"')
                    # 3. Remove trailing commas from arrays and objects
                    advisories_js = re.sub(r',\s*([}\]])', r'\1', advisories_js)

                    try:
                        advisories_list = json.loads(advisories_js)
                        for adv in advisories_list:
                            advisories.append({
                                'id': adv['ID'],
                                'url': adv['link'],
                                'products': [p[0] for p in adv.get('products', [])]
                            })
                    except json.JSONDecodeError as e:
                        self.logger.error("JSON decoding error: %s", e)
                        return []

            # Deduplicate
            seen = set()
            unique_advisories = []
            for adv in advisories:
                if adv['id'] not in seen:
                    seen.add(adv['id'])
                    unique_advisories.append(adv)
            
            self.logger.info("Found %d unique advisories", len(unique_advisories))
            return sorted(unique_advisories, key=lambda x: x['id'])
            
        except Exception as e:
            self.logger.error("Error during fetch: %s", e)
            return []
    
    def parse_advisory_page(self, url, advisory_id, products=None):
        """Parse an advisory page to extract all details."""
        try:
            self.logger.debug("Parsing %s...", advisory_id)
            response = self.session.get(url, timeout=30)
            # Handle 404 errors gracefully
            if response.status_code == 404:
                self.logger.warning("Page not found (404) for advisory %s", advisory_id)
                # We can still proceed with the data we have
                soup = BeautifulSoup("", 'html.parser')
            else:
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'html.parser')

            advisory_data = {
                'id': advisory_id,
                'url': url,
                'title': '',
                'date': '',
                'cves': [],
                'products': products if products else [],
                'product_versions': {},
                'fixed_versions': [],
                'severity': '',
                'cvss_score': None,
                'cvss_vector': None,
                'description': '',
                'references': [],
                'summary': ''
            }

            # Extract title
            title_elem = soup.find('h1', class_='entry-title')
            if title_elem:
                advisory_data['title'] = title_elem.get_text(strip=True)

            # Extract content
            content = soup.find('div', class_='entry-content') or soup.find('article')
            if content:
                text = content.get_text(separator='\n', strip=True)
                advisory_data['description'] = text
                advisory_data['summary'] = text[:500] + ('...' if len(text) > 500 else '')

                # Search for CVEs
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, text, re.IGNORECASE)
                advisory_data['cves'] = sorted(list(set(cve.upper() for cve in cves)))

                # Search for CVSS scores (base, temporal, environmental)
                advisory_data['cvss_score'] = None
                advisory_data['cvss_temporal_score'] = None
                advisory_data['cvss_environmental_score'] = None
                advisory_data['cvss_v2_score'] = None
                
                # Detect CVSS version used in the advisory
                has_cvss_v2 = bool(re.search(r'CVSS v2', text, re.IGNORECASE))
                has_cvss_v3 = bool(re.search(r'CVSS Base score', text, re.IGNORECASE))
                advisory_data['has_cvss_v2'] = has_cvss_v2
                advisory_data['has_cvss_v3'] = has_cvss_v3
                
                
                # Extract CVSS v3 scores - text format (e.g., "CVSS Base score: 5")
                cvss_base_match = re.search(r'CVSS Base score:[\s]*([\d.]+)', text, re.IGNORECASE)
                if cvss_base_match:
                    try:
                        advisory_data['cvss_score'] = float(cvss_base_match.group(1))
                    except:
                        pass
                
                cvss_temporal_match = re.search(r'CVSS Temporal score:[\s]*([\d.]+)', text, re.IGNORECASE)
                if cvss_temporal_match:
                    try:
                        advisory_data['cvss_temporal_score'] = float(cvss_temporal_match.group(1))
                    except:
                        pass
                
                cvss_env_match = re.search(r'CVSS Environmental score:[\s]*([\d.]+)', text, re.IGNORECASE)
                if cvss_env_match:
                    try:
                        advisory_data['cvss_environmental_score'] = float(cvss_env_match.group(1))
                    except:
                        pass
                
                # Extract CVSS v2 scores - text format (e.g., "CVSS v2 Overall Score: 2.8")
                cvss_v2_match = re.search(r'CVSS v2.*?([\d.]+)', text, re.IGNORECASE)
                if cvss_v2_match:
                    try:
                        advisory_data['cvss_v2_score'] = float(cvss_v2_match.group(1))
                    except:
                        pass
                
                # Extract CVSS scores with their types
                cvss_score_pattern = r'(CVSS:\d+\.\d+/(?:[A-Za-z0-9:/]+))'
                all_scores = re.findall(cvss_score_pattern, text)
                
                for score_vector in all_scores:
                    # Extract numeric score
                    score_match = re.search(r'CVSS:\d+\.\d+/.*/([A-Za-z]+):(\d+\.?\d*)', score_vector)
                    if score_match:
                        score_type = score_match.group(1).lower()  # AV, AC, etc.
                        score_value = float(score_match.group(2))
                        
                        # Determine score type (base, temporal, environmental)
                        if '/T:' in score_vector or '/T:' in score_vector.upper():
                            advisory_data['cvss_temporal_score'] = score_value
                        elif '/E:' in score_vector or '/E:' in score_vector.upper():
                            advisory_data['cvss_environmental_score'] = score_value
                        else:
                            # Base score
                            advisory_data['cvss_score'] = score_value
                
                # If no specific score found, try the simple pattern
                if advisory_data['cvss_score'] is None:
                    cvss_pattern = r'CVSS[:\s]*(\d+\.?\d*)'
                    cvss_match = re.search(cvss_pattern, text, re.IGNORECASE)
                    if cvss_match:
                        try:
                            advisory_data['cvss_score'] = float(cvss_match.group(1))
                        except:
                            pass
                
                # If still no score, try extracting from HTML tables
                if advisory_data['cvss_score'] is None:
                    # Search for tables with specific classes
                    tables = content.find_all('div', class_='div_table_col')
                    for i, table_col in enumerate(tables):
                        col_text = table_col.get_text(strip=True)
                        if 'CVSS' in col_text and i + 1 < len(tables):
                            score_text = tables[i + 1].get_text(strip=True)
                            try:
                                advisory_data['cvss_score'] = float(score_text)
                                if not advisory_data.get('cvss_version'): # Do not overwrite if already found via vector
                                    if 'v3' in col_text.lower():
                                        advisory_data['cvss_version'] = "3.1" # Default to 3.1 for v3
                                    elif 'v2' in col_text.lower():
                                        advisory_data['cvss_version'] = "2.0"
                                break
                            except (ValueError, TypeError):
                                pass
                
                # Calculate severity based on the base score
                if advisory_data['cvss_score']:
                    advisory_data['severity'] = self._get_severity(advisory_data['cvss_score'])

                # Search for CVSS vectors (base, temporal, environmental)
                advisory_data['cvss_vectors'] = { 'base': None, 'temporal': None, 'environmental': None }
                if 'cvss_version' not in advisory_data:
                    advisory_data['cvss_version'] = None
                
                # Regex to find vector blocks that are between parentheses
                vector_block_pattern = r'CVSS (Base|Temporal|Environmental) score:.*?\((.*?)\)'
                vector_blocks = re.findall(vector_block_pattern, text, re.DOTALL)

                for score_type, vector_part in vector_blocks:
                    vector_part = vector_part.strip().replace('\n', '')
                    
                    # Determine version from vector content
                    version = "3.1" # Default
                    if 'Au:' in vector_part:
                        version = "2.0"
                    elif 'PR:' in vector_part or 'UI:' in vector_part or 'S:' in vector_part:
                        version = "3.1"
                        
                    if not advisory_data.get('cvss_version'):
                        advisory_data['cvss_version'] = version

                    full_vector = f"CVSS:{version}/{vector_part}"
                    
                    type_key = score_type.lower()
                    if type_key in advisory_data['cvss_vectors']:
                        advisory_data['cvss_vectors'][type_key] = full_vector
                
                # Attempt to find floating vectors (without a score label)
                if not advisory_data['cvss_vectors']['base']:
                    vector_pattern = r'\(CVSS:(?:\d\.\d/)?([A-Za-z0-9:/]+)\)'
                    floating_vectors = re.findall(vector_pattern, text)
                    if floating_vectors:
                        # Take the first one, hoping it's the base vector
                        vector_part = floating_vectors[0]
                        version = "3.1" # Default
                        if 'Au:' in vector_part:
                            version = "2.0"
                        elif 'PR:' in vector_part or 'UI:' in vector_part or 'S:' in vector_part:
                            version = "3.1"
                        
                        if not advisory_data.get('cvss_version'):
                            advisory_data['cvss_version'] = version
                        
                        advisory_data['cvss_vectors']['base'] = f"CVSS:{version}/{vector_part}"

                # For backward compatibility
                advisory_data['cvss_vector'] = advisory_data['cvss_vectors']['base']


                # Extract versions per product
                product_sections = content.find_all('h2', class_='product')
                for section in product_sections:
                    product_name = section.get_text(strip=True)
                    if product_name in advisory_data['products']:
                        version_table = section.find_parent('table').find_next_sibling('table')
                        if version_table:
                            header_row = version_table.find('tr')
                            if header_row:
                                headers = header_row.find_all('h2')
                                version_col_index = -1
                                for i, header in enumerate(headers):
                                    if 'Impacted version' in header.get_text():
                                        version_col_index = i
                                        break
                                
                                if version_col_index != -1:
                                    data_row = header_row.find_next_sibling('tr')
                                    if data_row:
                                        version_cells = data_row.find_all('td')
                                        if version_col_index < len(version_cells):
                                            versions_cell = version_cells[version_col_index]
                                            versions = [li.get_text(strip=True) for li in versions_cell.find_all('li')]
                                            advisory_data['product_versions'][product_name] = versions
            
            # Publication date
            date_elem = soup.find('time', class_='entry-date')
            if date_elem:
                advisory_data['date'] = date_elem.get('datetime', '')

            self.logger.debug("Parsing %s... ✓", advisory_id)
            return advisory_data

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.logger.warning("Page not found (404) for %s", advisory_id)
                # Create a partial advisory_data
                return {
                    'id': advisory_id,
                    'url': url,
                    'title': f"Advisory {advisory_id} (page not found)",
                    'date': '',
                    'cves': [],
                    'products': products if products else [],
                    'product_versions': {},
                    'fixed_versions': [],
                    'severity': '',
                    'cvss_score': None,
                    'cvss_vector': None,
                    'description': 'Could not retrieve advisory details.',
                    'references': [],
                    'summary': 'Could not retrieve advisory details.'
                }
            else:
                self.logger.error("HTTP error for %s: %s", advisory_id, e)
                return None
        except Exception as e:
            self.logger.error("Parsing error for %s: %s", advisory_id, e)
            return None
    
    def _get_cpe_version(self, version_string):
        """Extract appropriate version string for CPE from version text."""
        # Handle version ranges
        if ' to ' in version_string:
            return '*'
        
        # Handle "and" cases (multiple versions)
        if ' and ' in version_string:
            return '*'
            
        # Extract version number from text like "SNS 1.0.0"
        # Look for version patterns
        version_match = re.search(r'(\d+\.\d+\.\d+)|(\d+\.\d+)', version_string)
        if version_match:
            return version_match.group(0)
        
        # Fallback: try to get last part after space
        parts = version_string.split(' ')
        if len(parts) > 1:
            return parts[-1]
        
        return version_string

    def _get_purl_version(self, version_string):
        """Generate appropriate version string for PURL from version text."""
        # For PURL, we need to handle ranges and multiple versions differently
        
        # Handle version ranges
        if ' to ' in version_string:
            match = re.search(r'([\d./]+)\s+to\s+([\d./]+)', version_string)
            if match:
                start_version = match.group(1)
                end_version = match.group(2)
                return f"{start_version}-{end_version}"
        
        # Handle "and" cases (multiple versions)
        if ' and ' in version_string:
            versions = []
            for part in version_string.split(' and '):
                version_match = re.search(r'(\d+\.\d+\.\d+)|(\d+\.\d+)', part)
                if version_match:
                    versions.append(version_match.group(0))
            return ".".join(versions) if versions else "unknown"
        
        # Extract version number from text
        version_match = re.search(r'(\d+\.\d+\.\d+)|(\d+\.\d+)', version_string)
        if version_match:
            return version_match.group(0)
        
        # Fallback: clean up the version string
        cleaned = re.sub(r'[^\w\d\.\-]', '_', version_string)
        return cleaned

    def _get_version_range_string(self, version_string):
        match = re.search(r'([\d./]+)\s+to\s+([\d./]+)', version_string)
        if match:
            start_version = match.group(1)
            end_version = match.group(2)
            return f">={start_version} <={end_version}"
        return ""
    
    def _get_severity(self, cvss_score):
        """Converts a CVSS score to a severity level."""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def generate_csaf_vex(self, advisory_data):
        """Generates a CSAF VEX document (CISA format)."""
        doc_id = f"stormshield-{advisory_data['id']}"
        timestamp = datetime.now().isoformat() + 'Z'
        
        csaf_doc = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": advisory_data['title'] or f"Stormshield Security Advisory {advisory_data['id']}",
                "publisher": {
                    "category": "vendor",
                    "name": "Stormshield",
                    "namespace": "https://advisories.stormshield.eu"
                },
                "tracking": {
                    "id": doc_id,
                    "status": "final",
                    "version": "1.0.0",
                    "revision_history": [
                        {
                            "number": "1.0.0",
                            "date": timestamp,
                            "summary": "Initial VEX document generation"
                        }
                    ],
                    "initial_release_date": advisory_data['date'] or timestamp,
                    "current_release_date": timestamp,
                    "generator": {
                        "engine": {
                            "name": "StormshieldMultiFormatGenerator",
                            "version": "1.0.0"
                        }
                    }
                },
                "notes": [
                    {
                        "category": "description",
                        "text": advisory_data['summary'],
                        "title": "Advisory Description"
                    }
                ],
                "references": [
                    {
                        "url": advisory_data['url'],
                        "summary": f"Stormshield Advisory {advisory_data['id']}"
                    }
                ]
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "Stormshield",
                        "branches": []
                    }
                ],
                "full_product_names": []
            },
            "vulnerabilities": []
        }
        
        # Add products
        products_list = advisory_data['products'] if advisory_data['products'] else ['Stormshield Product']
        affected_product_ids = []
        for product in products_list:
            product_versions = advisory_data.get('product_versions', {}).get(product, ['affected'])
            
            product_branches = []
            for version in product_versions:
                # Handle "and" cases - split into multiple versions
                if ' and ' in version:
                    for sub_version in version.split(' and '):
                        sub_version = sub_version.strip()
                        version_safe = sub_version.replace(' ', '_').lower()
                        product_id = f"{product.lower().replace(' ', '_')}_{version_safe}"
                        affected_product_ids.append(product_id)
                        product_branch = {
                            "category": "product_version",
                            "name": sub_version,
                            "product": {
                                "product_id": product_id,
                                "name": sub_version,
                                "product_identification_helper": {
                                    "purl": f"pkg:generic/stormshield/{product.lower().replace(' ', '-')}@{self._get_purl_version(sub_version)}",
                                    "cpe": f"cpe:2.3:a:stormshield:{product.lower().replace(' ', '_')}:{self._get_cpe_version(sub_version)}:*:*:*:*:*:*:*"
                                }
                            }
                        }
                        product_branches.append(product_branch)
                else:
                    version_safe = version.replace(' ', '_').lower()
                    product_id = f"{product.lower().replace(' ', '_')}_{version_safe}"
                    affected_product_ids.append(product_id)
                    product_branch = {
                        "category": "product_version",
                        "name": version,
                        "product": {
                            "product_id": product_id,
                            "name": version,
                                                            "product_identification_helper": {
                                                                "purl": f"pkg:generic/stormshield/{product.lower().replace(' ', '-')}@{self._get_purl_version(version)}",
                                                                "cpe": f"cpe:2.3:a:stormshield:{product.lower().replace(' ', '_')}:{self._get_cpe_version(version)}:*:*:*:*:*:*:*"
                                                            }                        }
                    }
                    product_branches.append(product_branch)

            # Create a branch for the product name and attach versions to it
            main_product_branch = {
                "category": "product_name",
                "name": product,
                "branches": product_branches
            }
            csaf_doc["product_tree"]["branches"][0]["branches"].append(main_product_branch)
        
        # Add CVEs
        if advisory_data['cves']:
            for cve in advisory_data['cves']:
                vulnerability = {
                    "cve": cve,
                    "product_status": {
                        "known_affected": affected_product_ids
                    },
                    "notes": [
                        {
                            "category": "description",
                            "text": f"Vulnerability {cve} as described in Stormshield advisory {advisory_data['id']}"
                        }
                    ]
                }
                
                if advisory_data.get('cvss_score') is not None:
                    cvss_version = advisory_data.get('cvss_version')
                    score_entry = {}

                    # Fallback
                    if not cvss_version:
                        if advisory_data['cvss_vectors']['base'] and 'Au:' in advisory_data['cvss_vectors']['base']:
                            cvss_version = "2.0"
                        else:
                            cvss_version = "3.1"

                    if cvss_version == "2.0":
                        cvss_v2_score = {
                            "version": "2.0",
                            "baseScore": advisory_data['cvss_score'],
                        }
                        if advisory_data['cvss_vectors']['base']:
                            cvss_v2_score['vectorString'] = advisory_data['cvss_vectors']['base']
                        if advisory_data.get('cvss_temporal_score'):
                            cvss_v2_score["temporalScore"] = advisory_data['cvss_temporal_score']
                        if advisory_data.get('cvss_environmental_score'):
                            cvss_v2_score["environmentalScore"] = advisory_data['cvss_environmental_score']
                        score_entry['cvss_v2'] = cvss_v2_score
                    else: # v3.x
                        cvss_v3_score = {
                            "version": cvss_version if cvss_version in ["3.0", "3.1"] else "3.1",
                            "baseScore": advisory_data['cvss_score'],
                            "baseSeverity": advisory_data['severity'].upper(),
                        }
                        if advisory_data['cvss_vectors']['base']:
                            cvss_v3_score['vectorString'] = advisory_data['cvss_vectors']['base']
                        if advisory_data.get('cvss_temporal_score'):
                            cvss_v3_score["temporalScore"] = advisory_data['cvss_temporal_score']
                        if advisory_data.get('cvss_environmental_score'):
                            cvss_v3_score["environmentalScore"] = advisory_data['cvss_environmental_score']
                        if advisory_data['cvss_vectors']['environmental']:
                            cvss_v3_score["environmentalVector"] = advisory_data['cvss_vectors']['environmental']
                        score_entry['cvss_v3'] = cvss_v3_score

                    vulnerability["scores"] = [score_entry]
                
                csaf_doc["vulnerabilities"].append(vulnerability)
        
        return csaf_doc
    

    
    def generate_csaf_cve_individual(self, advisory_data, cve):
        """Generates an individual CSAF document for a CVE (for Dependency-Track)."""
        doc_id = f"{cve.lower()}-stormshield-{advisory_data['id']}"
        timestamp = datetime.now().isoformat() + 'Z'
        
        csaf_doc = {
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "title": f"{cve} - {advisory_data['title'][:100]}",
                "publisher": {
                    "category": "vendor",
                    "name": "Stormshield",
                    "namespace": "https://advisories.stormshield.eu"
                },
                "tracking": {
                    "id": doc_id,
                    "status": "final",
                    "version": "1.0.0",
                    "revision_history": [
                        {
                            "number": "1.0.0",
                            "date": timestamp,
                            "summary": "Initial release"
                        }
                    ],
                    "initial_release_date": advisory_data['date'] or timestamp,
                    "current_release_date": timestamp,
                    "generator": {
                        "engine": {
                            "name": "StormshieldMultiFormatGenerator",
                            "version": "1.0.0"
                        }
                    }
                },
                "notes": [
                    {
                        "category": "summary",
                        "text": advisory_data['summary'],
                        "title": "Summary"
                    }
                ],
                "references": [
                    {
                        "url": advisory_data['url'],
                        "summary": f"Stormshield Advisory {advisory_data['id']}"
                    },
                    {
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                        "summary": f"NVD entry for {cve}"
                    }
                ],
                "distribution": {
                    "tlp": {
                        "label": "GREEN"
                    }
                },
                "lang": "en"
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "Stormshield",
                        "branches": []
                    }
                ],
                "full_product_names": []
            },
            "vulnerabilities": [
                {
                    "cve": cve,
                    "product_status": {
                        "known_affected": []
                    },
                    "notes": [
                        {
                            "category": "description",
                            "text": f"Vulnerability {cve} affects Stormshield products. See advisory {advisory_data['id']} for details."
                        }
                    ]
                }
            ]
        }
        
        # Add affected products
        products_list = advisory_data['products'] if advisory_data['products'] else ['Stormshield Product']
        for product in sorted(products_list):
            product_versions = advisory_data.get('product_versions', {}).get(product, ['affected'])
            
            version_branches = []
            for version in sorted(product_versions):
                # Handle "and" cases - split into multiple versions
                if ' and ' in version:
                    for sub_version in sorted(version.split(' and ')):
                        sub_version = sub_version.strip()
                        version_safe = sub_version.replace(' ', '_').lower()
                        branch_product_id = f"branch_{product.lower().replace(' ', '_')}_{version_safe}"
                        full_product_id = f"{product.lower().replace(' ', '_')}_{version_safe}"
                        csaf_doc["vulnerabilities"][0]["product_status"]["known_affected"].append(full_product_id)

                        # Structure for the product_version branch
                        version_branch = {
                            "category": "product_version",
                            "name": sub_version,
                            "product": {
                                "product_id": branch_product_id,
                                "name": sub_version,
                                "product_identification_helper": {
                                    "purl": f"pkg:generic/stormshield/{product.lower().replace(' ', '-')}@{self._get_purl_version(sub_version)}",
                                    "cpe": f"cpe:2.3:a:stormshield:{product.lower().replace(' ', '_')}:{self._get_cpe_version(sub_version)}:*:*:*:*:*:*:*"
                                }
                            }
                        }
                        version_branches.append(version_branch)
                else:
                    version_safe = version.replace(' ', '_').lower()
                    branch_product_id = f"branch_{product.lower().replace(' ', '_')}_{version_safe}"
                    full_product_id = f"{product.lower().replace(' ', '_')}_{version_safe}"
                    csaf_doc["vulnerabilities"][0]["product_status"]["known_affected"].append(full_product_id)

                    # Structure for the product_version branch
                    version_branch = {
                        "category": "product_version",
                        "name": version,
                        "product": {
                            "product_id": branch_product_id,
                            "name": version,
                                                            "product_identification_helper": {
                                                                "purl": f"pkg:generic/stormshield/{product.lower().replace(' ', '-')}@{self._get_purl_version(version)}",
                                                                "cpe": f"cpe:2.3:a:stormshield:{product.lower().replace(' ', '_')}:{self._get_cpe_version(version)}:*:*:*:*:*:*:*"
                                                            }                        }
                    }
                    version_branches.append(version_branch)
            
            product_branch = {
                "category": "product_name",
                "name": product,
                "branches": sorted(version_branches, key=lambda x: x.get('name', ''))
            }
            csaf_doc["product_tree"]["branches"][0]["branches"].append(product_branch)
            
            # Add products to full_product_names for CSAF validation
            for version in sorted(product_versions):
                if ' and ' in version:
                    for sub_version in sorted(version.split(' and ')):
                        sub_version = sub_version.strip()
                        version_safe = sub_version.replace(' ', '_').lower()
                        full_product_id = f"{product.lower().replace(' ', '_')}_{version_safe}"
                        
                        # Add to full_product_names
                        csaf_doc["product_tree"]["full_product_names"].append({
                            "product_id": full_product_id,
                            "name": sub_version
                        })
                else:
                    version_safe = version.replace(' ', '_').lower()
                    full_product_id = f"{product.lower().replace(' ', '_')}_{version_safe}"
                    
                    # Add to full_product_names
                    csaf_doc["product_tree"]["full_product_names"].append({
                        "product_id": full_product_id,
                        "name": version
                    })
        
        # Sort product tree branches
        csaf_doc["product_tree"]["branches"][0]["branches"] = sorted(
            csaf_doc["product_tree"]["branches"][0]["branches"], 
            key=lambda x: x.get('name', '')
        )
        
        # Sort full_product_names
        csaf_doc["product_tree"]["full_product_names"] = sorted(
            csaf_doc["product_tree"]["full_product_names"], 
            key=lambda x: x.get('product_id', '')
        )
        
        # Use the CVSS version determined during parsing
        cvss_version = advisory_data.get('cvss_version')

        if advisory_data.get('cvss_score') is not None:
            score_entry = {
                "products": csaf_doc["vulnerabilities"][0]["product_status"]["known_affected"]
            }

            # Fallback if no version could be detected
            if not cvss_version:
                # If we have a vector, we can try to guess again
                if advisory_data['cvss_vectors']['base'] and 'Au:' in advisory_data['cvss_vectors']['base']:
                    cvss_version = "2.0"
                else:
                    cvss_version = "3.1" # Otherwise, assume v3.1 by default

            # Build the score object based on the version
            if cvss_version == "2.0":
                cvss_v2_score = {
                    "version": "2.0",
                    "baseScore": advisory_data['cvss_score'],
                }
                if advisory_data['cvss_vectors']['base']:
                    cvss_v2_score['vectorString'] = advisory_data['cvss_vectors']['base']
                if advisory_data.get('cvss_temporal_score'):
                    cvss_v2_score["temporalScore"] = advisory_data['cvss_temporal_score']
                if advisory_data.get('cvss_environmental_score'):
                    cvss_v2_score["environmentalScore"] = advisory_data['cvss_environmental_score']

                score_entry['cvss_v2'] = cvss_v2_score
            
            else: # Treat as CVSS v3.x
                cvss_v3_score = {
                    "version": cvss_version if cvss_version in ["3.0", "3.1"] else "3.1",
                    "baseScore": advisory_data['cvss_score'],
                    "baseSeverity": advisory_data['severity'].upper(),
                }
                if advisory_data['cvss_vectors']['base']:
                    cvss_v3_score['vectorString'] = advisory_data['cvss_vectors']['base']
                if advisory_data.get('cvss_temporal_score'):
                    cvss_v3_score["temporalScore"] = advisory_data['cvss_temporal_score']
                if advisory_data.get('cvss_environmental_score'):
                    cvss_v3_score["environmentalScore"] = advisory_data['cvss_environmental_score']
                if advisory_data['cvss_vectors']['environmental']:
                    cvss_v3_score["environmentalVector"] = advisory_data['cvss_vectors']['environmental']

                score_entry['cvss_v3'] = cvss_v3_score

            csaf_doc["vulnerabilities"][0]["scores"] = [score_entry]
        
        # Affected products must remain simple IDs in known_affected
        # Additional information should be in the product structure
        known_affected_ids = csaf_doc["vulnerabilities"][0]["product_status"]["known_affected"]
        csaf_doc["vulnerabilities"][0]["product_status"]["known_affected"] = sorted(known_affected_ids)
        
        # Affected products are already sorted, no need to re-sort
        
        # Sort references
        csaf_doc["document"]["references"] = sorted(
            csaf_doc["document"]["references"], 
            key=lambda x: x.get("url", "")
        )
        
        # Add a canonical URL
        for ref in csaf_doc["document"]["references"]:
            if ref.get("category") == "self":
                ref["canonical"] = True
                break
        
        # Sort notes
        if "notes" in csaf_doc["document"]:
            csaf_doc["document"]["notes"] = sorted(
                csaf_doc["document"]["notes"], 
                key=lambda x: x.get("category", "")
            )
        
        # Sort vulnerabilities
        csaf_doc["vulnerabilities"] = sorted(
            csaf_doc["vulnerabilities"], 
            key=lambda x: x.get("cve", "")
        )
        
        # Sort dictionary keys to respect alphabetical order
        def sort_dict_keys(obj):
            if isinstance(obj, dict):
                return {k: sort_dict_keys(v) for k, v in sorted(obj.items())}
            elif isinstance(obj, list):
                return [sort_dict_keys(v) for v in obj]
            else:
                return obj
        
        csaf_doc = sort_dict_keys(csaf_doc)
        
        return csaf_doc
    
    def save_documents(self, advisory_data):
        """Saves all formats for a given advisory."""
        try:
            # 1. CSAF VEX
            csaf_vex = self.generate_csaf_vex(advisory_data)
            csaf_vex_file = self.csaf_vex_dir / f"stormshield-{advisory_data['id']}.json"
            with open(csaf_vex_file, 'w', encoding='utf-8') as f:
                json.dump(csaf_vex, f, indent=2, ensure_ascii=False)
            
            # 3. CSAF Individual CVEs (one file per CVE)
            for cve in advisory_data['cves']:
                csaf_cve = self.generate_csaf_cve_individual(advisory_data, cve)
                cve_safe = cve.lower().replace('-', '_')
                csaf_cve_file = self.csaf_cve_dir / f"{cve_safe}-{advisory_data['id']}.json"
                with open(csaf_cve_file, 'w', encoding='utf-8') as f:
                    json.dump(csaf_cve, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            self.logger.error("Error saving documents for %s: %s", advisory_data['id'], e)
            return False

    def load_processed_index(self):
        """Loads the index of already processed advisories."""
        if not self.index_file.exists():
            return set()
        try:
            with open(self.index_file, 'r', encoding='utf-8') as f:
                processed_ids = json.load(f)
                self.logger.info("Loaded %d IDs from local index.", len(processed_ids))
                return set(processed_ids)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.warning("Could not read index file %s. It will be recreated. Error: %s", self.index_file, e)
            return set()

    def update_processed_index(self, processed_ids):
        """Updates the index file with processed IDs."""
        try:
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(sorted(list(processed_ids)), f, indent=2, ensure_ascii=False)
        except IOError as e:
            self.logger.error("Error while updating the index file: %s", e)

    def _process_single_advisory(self, advisory):
        """Processes a single advisory: parses and saves the documents."""
        self.logger.info("Processing %s", advisory['id'])
        advisory_data = self.parse_advisory_page(advisory['url'], advisory['id'], advisory.get('products', []))
        
        if advisory_data:
            if self.save_documents(advisory_data):
                # Return the ID and CVE count for counting
                return advisory_data['id'], len(advisory_data['cves'])
        return None, 0
    
    def generate_all_formats(self, max_advisories=None):
        """Generates all formats for NEW advisories in parallel."""
        all_advisories = self.fetch_all_advisories()
        
        if not all_advisories:
            self.logger.warning("No advisories found on the website!")
            return

        processed_ids = self.load_processed_index()
        advisories_to_process = [adv for adv in all_advisories if adv['id'] not in processed_ids]

        if not advisories_to_process:
            self.logger.info("✓ No new advisories to process. Everything is up to date.")
            return

        if max_advisories:
            advisories_to_process = advisories_to_process[:max_advisories]
            self.logger.info("Limiting to %d new advisories for testing", max_advisories)

        self.logger.info("Generating all formats for %d new advisories...", len(advisories_to_process))
        self.logger.info("Output directory: %s", self.base_dir.absolute())
        self.logger.info("  - CSAF VEX: %s", self.csaf_vex_dir)
        self.logger.info("  - CSAF CVE: %s", self.csaf_cve_dir)
        
        success_count = 0
        total_cves = 0
        newly_processed_ids = set()
        
        parallel_workers = self.config.getint('Performance', 'parallel_workers', fallback=4)
        
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            future_to_advisory = {executor.submit(self._process_single_advisory, adv): adv for adv in advisories_to_process}
            
            for future in as_completed(future_to_advisory):
                advisory = future_to_advisory[future]
                try:
                    processed_id, cve_count = future.result()
                    if processed_id:
                        success_count += 1
                        total_cves += cve_count
                        newly_processed_ids.add(processed_id)
                except Exception as exc:
                    self.logger.error("%r generated an exception: %s", advisory['id'], exc)

        if newly_processed_ids:
            updated_ids = processed_ids.union(newly_processed_ids)
            self.update_processed_index(updated_ids)
            self.logger.info("Index updated with %d new advisories.", len(newly_processed_ids))

        self.logger.info("="*70)
        self.logger.info("✓ Finished: %d/%d new advisories processed", success_count, len(advisories_to_process))
        self.logger.info("✓ Total CVEs in this session: %d", total_cves)
        self.logger.info("✓ Generated files:")
        self.logger.info("  - %d CSAF VEX in total", len(list(self.csaf_vex_dir.glob('*.json'))))
        self.logger.info("  - %d CSAF CVE individuals in total", len(list(self.csaf_cve_dir.glob('*.json'))))
        self.logger.info("✓ Directory: %s", self.base_dir.absolute())
        self.logger.info("="*70)
    
    def generate_indexes(self):
        """Generates index files for each format."""
        self.logger.info("Generating index files...")
        timestamp = datetime.now().isoformat()
        
        # CSAF VEX Index
        csaf_vex_files = list(self.csaf_vex_dir.glob("*.json"))
        csaf_vex_index = {
            "generated_at": timestamp,
            "total_documents": len(csaf_vex_files),
            "format": "CSAF VEX 2.0",
            "documents": []
        }
        
        for vex_file in sorted(csaf_vex_files):
            try:
                with open(vex_file, 'r', encoding='utf-8') as f:
                    doc = json.load(f)
                    csaf_vex_index["documents"].append({
                        "id": doc["document"]["tracking"]["id"],
                        "title": doc["document"]["title"],
                        "file": vex_file.name,
                        "cves": [v.get("cve") for v in doc.get("vulnerabilities", []) if "cve" in v]
                    })
            except Exception as e:
                self.logger.warning("Could not read CSAF VEX file %s for indexing: %s", vex_file.name, e)
                continue
        
        with open(self.csaf_vex_dir / "index.json", 'w', encoding='utf-8') as f:
            json.dump(csaf_vex_index, f, indent=2, ensure_ascii=False)
        
        # CSAF CVE Index
        csaf_cve_files = list(self.csaf_cve_dir.glob("*.json"))
        csaf_cve_index = {
            "generated_at": timestamp,
            "total_cve_documents": len(csaf_cve_files),
            "format": "CSAF 2.0 Security Advisory",
            "cves": {}
        }
        
        for cve_file in sorted(csaf_cve_files):
            try:
                with open(cve_file, 'r', encoding='utf-8') as f:
                    doc = json.load(f)
                    for vuln in doc.get("vulnerabilities", []):
                        cve = vuln.get("cve")
                        if cve:
                            if cve not in csaf_cve_index["cves"]:
                                csaf_cve_index["cves"][cve] = []
                            csaf_cve_index["cves"][cve].append(cve_file.name)
            except Exception as e:
                self.logger.warning("Could not read CSAF CVE file %s for indexing: %s", cve_file.name, e)
                continue
        
        with open(self.csaf_cve_dir / "index.json", 'w', encoding='utf-8') as f:
            json.dump(csaf_cve_index, f, indent=2, ensure_ascii=False)
        
        self.logger.info("✓ Indexes generated in each directory.")

def main():
    import argparse
    import configparser
    
    config = configparser.ConfigParser()
    config.read('config.ini')

    parser = argparse.ArgumentParser(
        description='Generate CSAF VEX and CSAF CVE from Stormshield advisories'
    )
    parser.add_argument(
        '--output-dir', '-o',
        default=config.get('General', 'output_dir', fallback='stormshield_output'),
        help='Main output directory'
    )
    parser.add_argument(
        '--max', '-m',
        type=int,
        help='Maximum number of advisories to process (for testing)'
    )
    parser.add_argument(
        '--index-only', '-i',
        action='store_true',
        help='Only generate indexes for existing documents'
    )
    
    args = parser.parse_args()
    
    generator = StormshieldMultiFormatGenerator(config=config, base_dir=args.output_dir)
    
    if args.index_only:
        generator.generate_indexes()
    else:
        generator.generate_all_formats(max_advisories=args.max)
        generator.generate_indexes()

if __name__ == "__main__":
    main()