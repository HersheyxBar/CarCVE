import requests
import json
import time
from typing import List, Dict, Optional
from datetime import datetime
import urllib.parse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RateLimiter:
    """Handles API rate limiting with exponential backoff"""
    
    def __init__(self, requests_per_period: int = 10, period_seconds: int = 60):
        self.requests_per_period = requests_per_period
        self.period_seconds = period_seconds
        self.request_times = []
    
    def wait_if_needed(self):
        """Wait if we're approaching rate limits"""
        now = time.time()
        
        # Remove old requests outside the time window
        self.request_times = [t for t in self.request_times if now - t < self.period_seconds]
        
        # If we're at the limit, wait
        if len(self.request_times) >= self.requests_per_period:
            sleep_time = self.period_seconds - (now - self.request_times[0]) + 1
            logger.info(f"Rate limit reached, waiting {sleep_time:.1f} seconds")
            time.sleep(sleep_time)
        
        # Add current request time
        self.request_times.append(now)
        time.sleep(2)  # Base delay between requests

class CVESearcher:
    """
    Professional CVE searcher with proper rate limiting and error handling
    """
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AutomotiveCyberSecurityScanner/1.0',
            'Accept': 'application/json'
        })
        self.rate_limiter = RateLimiter(requests_per_period=8, period_seconds=60)
        
        # Manufacturer-specific infotainment systems
        self.manufacturer_systems = {
            'ford': ['sync', 'ford pass'],
            'toyota': ['entune', 'toyota connect'],
            'honda': ['honda connect', 'honda sensing'],
            'bmw': ['idrive', 'bmw connected'],
            'mercedes': ['mbux', 'mercedes me'],
            'audi': ['mmi', 'audi connect'],
            'tesla': ['autopilot', 'tesla software'],
            'chrysler': ['uconnect'],
            'dodge': ['uconnect'],
            'jeep': ['uconnect'],
            'ram': ['uconnect'],
            'volkswagen': ['car-net'],
            'nissan': ['nissan connect'],
            'hyundai': ['bluelink'],
            'kia': ['uvo']
        }
    
    def search_vehicle_cves(self, make: str, model: str, year: Optional[str] = None, max_results: int = 50) -> List[Dict]:
        """
        Search for CVEs related to a specific vehicle with intelligent rate limiting
        
        Args:
            make: Vehicle manufacturer name
            model: Vehicle model name  
            year: Vehicle year (optional)
            max_results: Maximum number of results to return
            
        Returns:
            List of CVE dictionaries sorted by severity
        """
        logger.info(f"Starting CVE search for {make} {model} {year or ''}")
        all_results = []
        
        # Generate prioritized search queries
        search_queries = self._generate_prioritized_queries(make, model, year)
        
        # Execute searches with proper rate limiting
        for i, query in enumerate(search_queries[:3]):  # Limit to 3 most important queries
            try:
                logger.info(f"Executing query {i+1}/3: '{query}'")
                self.rate_limiter.wait_if_needed()
                
                results = self._execute_search_query(query, max_results=20)
                all_results.extend(results)
                
                logger.info(f"Found {len(results)} results for query '{query}'")
                
                # Stop if we have sufficient quality results
                if len(all_results) >= 15:
                    logger.info(f"Sufficient results found ({len(all_results)}), stopping search")
                    break
                    
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"Rate limited on query '{query}', stopping search")
                    break
                else:
                    logger.error(f"HTTP error for query '{query}': {e}")
                    continue
            except Exception as e:
                logger.error(f"Unexpected error for query '{query}': {e}")
                continue
        
        # Process and filter results
        processed_results = self._process_search_results(all_results, make, model)
        logger.info(f"Returning {len(processed_results)} relevant CVEs")
        
        return processed_results[:max_results]
    
    def _generate_prioritized_queries(self, make: str, model: str, year: Optional[str] = None) -> List[str]:
        """
        Generate prioritized search queries based on specificity and relevance
        
        Returns queries in order of importance:
        1. Direct vehicle identification
        2. Manufacturer-specific systems
        3. General manufacturer vulnerabilities
        """
        queries = []
        make_lower = make.lower()
        
        # Priority 1: Most specific - exact vehicle match
        base_query = f"{make} {model}"
        queries.append(base_query)
        
        # Priority 2: Manufacturer-specific infotainment systems
        if make_lower in self.manufacturer_systems:
            for system in self.manufacturer_systems[make_lower]:
                queries.append(f"{make} {system}")
        else:
            # Fallback for manufacturers not in our system mapping
            queries.append(f"{make} infotainment")
        
        # Priority 3: General manufacturer search
        queries.append(make)
        
        logger.info(f"Generated {len(queries)} prioritized queries for {make} {model}")
        return queries
    
    def _execute_search_query(self, query: str, max_results: int = 20) -> List[Dict]:
        """
        Execute a single CVE search query with proper error handling
        
        Args:
            query: Search term for NVD API
            max_results: Maximum results to return from this query
            
        Returns:
            List of parsed CVE dictionaries
        """
        try:
            encoded_query = urllib.parse.quote(query)
            url = f"{self.base_url}?keywordSearch={encoded_query}&resultsPerPage={min(max_results, 2000)}"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'vulnerabilities' not in data:
                logger.warning(f"No vulnerabilities found in response for query: {query}")
                return []
            
            results = []
            for vuln in data['vulnerabilities']:
                parsed_cve = self._parse_cve_data(vuln)
                if parsed_cve:
                    results.append(parsed_cve)
            
            return results
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error while searching CVEs for '{query}': {str(e)}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response for query '{query}': {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error searching CVEs for '{query}': {str(e)}")
            return []
    
    def _process_search_results(self, all_results: List[Dict], make: str, model: str) -> List[Dict]:
        """
        Process raw search results through deduplication, filtering, and sorting
        
        Args:
            all_results: Raw CVE results from all queries
            make: Vehicle manufacturer for relevance filtering
            model: Vehicle model for relevance filtering
            
        Returns:
            Processed and sorted list of relevant CVEs
        """
        logger.info(f"Processing {len(all_results)} raw CVE results")
        
        # Step 1: Remove duplicates
        unique_results = self._deduplicate_results(all_results)
        logger.info(f"After deduplication: {len(unique_results)} CVEs")
        
        # Step 2: Filter for relevance to the specific vehicle
        relevant_results = self._filter_relevant_results(unique_results, make, model)
        logger.info(f"After relevance filtering: {len(relevant_results)} CVEs")
        
        # Step 3: Sort by severity (Critical -> High -> Medium -> Low)
        sorted_results = self._sort_by_severity(relevant_results)
        
        return sorted_results
    

    
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
