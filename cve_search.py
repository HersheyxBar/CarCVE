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
        
        for query in search_queries[:4]:  # Reduce to 4 queries to avoid rate limiting
            try:
                # Add delay for rate limiting (NVD recommends no more than 50 requests in 30 seconds)
                time.sleep(3)  # Increase delay to avoid 429 errors
                
                results = self._search_cves_by_keyword(query, max_results=25)
                all_results.extend(results)
                
                # If we have enough results, break early to avoid rate limiting
                if len(all_results) >= 20:
                    break
                    
            except Exception as e:
                print(f"Error searching with query '{query}': {str(e)}")
                continue
        
        # Skip broader searches to avoid rate limiting - focus on quality over quantity
        
        # Remove duplicates and filter for relevance
        unique_results = self._deduplicate_results(all_results)
        relevant_results = self._filter_relevant_results(unique_results, make, model)
        sorted_results = self._sort_by_severity(relevant_results)
        
        return sorted_results[:max_results]
    
    def _generate_search_queries(self, make: str, model: str, year: str = "") -> List[str]:
        """Generate prioritized search queries for CVE search"""
        queries = []
        
        # Priority 1: Direct vehicle searches - most specific and relevant
        queries.append(f"{make} {model}")
        if year and year.strip():
            queries.append(f"{make} {model} {year}")
        
        # Priority 2: Make with key automotive technologies
        queries.extend([
            f"{make} infotainment",
            f"{make} automotive"
        ])
        
        # Priority 3: Make-specific system searches
        if make.lower() == 'ford':
            queries.append("ford sync")
        elif make.lower() in ['chrysler', 'dodge', 'jeep', 'ram']:
            queries.append(f"{make} uconnect")
        elif make.lower() == 'toyota':
            queries.append("toyota entune")
        elif make.lower() == 'honda':
            queries.append("honda connect")
        elif make.lower() in ['bmw', 'mercedes', 'audi']:
            queries.append(f"{make} idrive" if make.lower() == 'bmw' else f"{make} command")
        else:
            queries.append(f"{make} connect")
        
        # Priority 4: General make search
        queries.append(make)
        
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
    
    def _filter_relevant_results(self, results: List[Dict], make: str, model: str) -> List[Dict]:
        """Filter results to ensure relevance to the specific vehicle"""
        relevant_results = []
        make_lower = make.lower()
        model_lower = model.lower()
        
        # Other car manufacturers to exclude when searching for specific make
        other_makes = {
            'tesla', 'ford', 'gm', 'general motors', 'chevrolet', 'toyota', 'honda', 
            'nissan', 'bmw', 'mercedes', 'audi', 'volkswagen', 'hyundai', 'kia',
            'mazda', 'subaru', 'lexus', 'acura', 'infiniti', 'cadillac', 'buick',
            'chrysler', 'dodge', 'jeep', 'ram', 'volvo', 'jaguar', 'land rover',
            'porsche', 'mini', 'mitsubishi', 'genesis'
        }
        
        # Remove the searched make from exclusion list
        other_makes.discard(make_lower)
        
        for result in results:
            description = result.get('description', '').lower()
            cve_id = result.get('id', '').lower()
            
            # Check if this CVE mentions other car manufacturers
            mentions_other_make = any(other_make in description for other_make in other_makes)
            
            # If it mentions the searched make/model or general automotive terms without other makes
            mentions_searched_make = make_lower in description or model_lower in description
            mentions_automotive = any(term in description for term in [
                'automotive', 'vehicle', 'car', 'infotainment', 'telematics', 
                'navigation', 'bluetooth', 'ecu', 'can bus'
            ])
            
            # Include if:
            # 1. Specifically mentions the searched make/model, OR
            # 2. Mentions automotive terms without mentioning other specific manufacturers
            if mentions_searched_make or (mentions_automotive and not mentions_other_make):
                relevant_results.append(result)
        
        return relevant_results
    
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
