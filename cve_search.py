import requests
import json
import time
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import urllib.parse

class CVESearcher:
    """
    CVE searcher using NVD API
    """
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AutomotiveCyberSecurityScanner/1.0'
        })
        
        # Automotive-related keywords for broader searches
        self.automotive_keywords = [
            'automotive', 'vehicle', 'car', 'truck', 'suv',
            'infotainment', 'telematics', 'ecu', 'electronic control unit',
            'can bus', 'obd', 'onboard diagnostic', 'bluetooth automotive',
            'gps navigation', 'dashboard', 'instrument cluster',
            'tire pressure', 'tpms', 'adaptive cruise control',
            'lane departure', 'collision avoidance', 'parking assist',
            'keyless entry', 'remote start', 'connected car',
            'v2x', 'vehicle to everything', 'over the air update'
        ]
    
    def search_vehicle_cves(self, make: str, model: str, year: Optional[str] = None, max_results: int = 50) -> List[Dict]:
        """
        Search for CVEs related to a specific vehicle
        
        Args:
            make (str): Vehicle make
            model (str): Vehicle model  
            year (str): Vehicle year (optional)
            max_results (int): Maximum number of results to return
            
        Returns:
            List of CVE dictionaries
        """
        all_results = []
        
        # Generate search queries
        search_queries = self._generate_search_queries(make, model, year if year else "")
        
        for query in search_queries[:8]:  # Increase to 8 queries for better coverage
            try:
                # Add delay for rate limiting (NVD recommends no more than 50 requests in 30 seconds)
                time.sleep(1)
                
                results = self._search_cves_by_keyword(query, max_results=30)
                all_results.extend(results)
                
                # Don't break early - we want comprehensive results
                    
            except Exception as e:
                print(f"Error searching with query '{query}': {str(e)}")
                continue
        
        # If we don't have many results, try broader searches
        if len(all_results) < 10:
            broader_queries = [
                "automotive",
                "vehicle",
                "car",
                "infotainment", 
                "telematics",
                "bluetooth automotive",
                "android automotive",
                "linux automotive"
            ]
            
            for query in broader_queries[:5]:
                try:
                    time.sleep(1)
                    results = self._search_cves_by_keyword(query, max_results=20)
                    all_results.extend(results)
                except Exception as e:
                    print(f"Error with broader search '{query}': {str(e)}")
                    continue
        
        # Remove duplicates and sort by severity
        unique_results = self._deduplicate_results(all_results)
        sorted_results = self._sort_by_severity(unique_results)
        
        return sorted_results[:max_results]
    
    def _generate_search_queries(self, make: str, model: str, year: str = "") -> List[str]:
        """Generate search queries for CVE search"""
        queries = []
        
        # Direct vehicle searches - these are most specific
        queries.append(f"{make} {model}")
        if year and year.strip():
            queries.append(f"{make} {model} {year}")
        
        # Make-only searches to catch broader vulnerabilities
        queries.append(make)
        
        # Common automotive technology searches
        queries.extend([
            f"{make} infotainment",
            f"{make} navigation", 
            f"{make} bluetooth",
            f"{make} wifi",
            f"{make} android",
            f"{make} linux",
            f"{make} uconnect" if make.lower() in ['chrysler', 'dodge', 'jeep', 'ram'] else f"{make} connect",
            f"{make} sync" if make.lower() == 'ford' else f"{make} system"
        ])
        
        # Broader technology searches that often affect vehicles
        queries.extend([
            "automotive bluetooth",
            "vehicle wifi", 
            "car android",
            "infotainment system",
            "telematics unit",
            "automotive linux",
            "vehicle navigation",
            "car entertainment",
            "automotive android",
            "vehicle connectivity",
            "automotive gateway",
            "can bus",
            "obd port",
            "tire pressure monitoring",
            "keyless entry",
            "remote start"
        ])
        
        return queries
    
    def _search_cves_by_keyword(self, keyword: str, max_results: int = 20) -> List[Dict]:
        """Search CVEs by keyword using NVD API"""
        try:
            # Encode the keyword for URL
            encoded_keyword = urllib.parse.quote(keyword)
            
            # Build API URL with parameters
            url = f"{self.base_url}?keywordSearch={encoded_keyword}&resultsPerPage={min(max_results, 2000)}"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'vulnerabilities' not in data:
                return []
            
            results = []
            for vuln in data['vulnerabilities']:
                cve_data = self._parse_cve_data(vuln)
                if cve_data:
                    results.append(cve_data)
            
            return results
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error while searching CVEs: {str(e)}")
        except json.JSONDecodeError:
            raise Exception("Invalid response from CVE database")
        except Exception as e:
            raise Exception(f"Error searching CVEs: {str(e)}")
    
    def _parse_cve_data(self, vuln_data: Dict) -> Optional[Dict]:
        """Parse CVE data from NVD API response"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get dates
            published_date = cve.get('published', '')
            modified_date = cve.get('lastModified', '')
            
            # Format dates
            if published_date:
                try:
                    pub_dt = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    published_date = pub_dt.strftime('%Y-%m-%d')
                except:
                    pass
            
            if modified_date:
                try:
                    mod_dt = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
                    modified_date = mod_dt.strftime('%Y-%m-%d')
                except:
                    pass
            
            # Get CVSS data
            severity = 'UNKNOWN'
            cvss_score = None
            
            metrics = vuln_data.get('cve', {}).get('metrics', {})
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric_data = metrics[version][0]
                    cvss_data = metric_data.get('cvssData', {})
                    
                    if 'baseScore' in cvss_data:
                        cvss_score = cvss_data['baseScore']
                        
                        # Determine severity based on score
                        if cvss_score >= 9.0:
                            severity = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
                        break
            
            # Get references
            references = []
            ref_data = cve.get('references', [])
            for ref in ref_data[:5]:  # Limit to first 5 references
                url = ref.get('url', '')
                if url:
                    references.append(url)
            
            return {
                'id': cve_id,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'published_date': published_date,
                'modified_date': modified_date,
                'references': references
            }
            
        except Exception as e:
            print(f"Error parsing CVE data: {str(e)}")
            return None
    
    def _deduplicate_results(self, results: List[Dict]) -> List[Dict]:
        """Remove duplicate CVEs from results"""
        seen_ids = set()
        unique_results = []
        
        for result in results:
            cve_id = result.get('id')
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                unique_results.append(result)
        
        return unique_results
    
    def _sort_by_severity(self, results: List[Dict]) -> List[Dict]:
        """Sort results by severity (Critical > High > Medium > Low > Unknown)"""
        severity_order = {
            'CRITICAL': 0,
            'HIGH': 1, 
            'MEDIUM': 2,
            'LOW': 3,
            'UNKNOWN': 4
        }
        
        return sorted(results, key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 4))
