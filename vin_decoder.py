import requests
import json
import time
from typing import Dict, Optional
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VINValidator:
    """Handles VIN validation with comprehensive checks"""
    
    @staticmethod
    def is_valid_format(vin: str) -> bool:
        """Check if VIN meets basic format requirements"""
        if not vin or len(vin) != 17:
            return False
        
        # Check for forbidden characters (I, O, Q are not used in VINs)
        forbidden_chars = set('IOQ')
        if any(char in forbidden_chars for char in vin.upper()):
            return False
        
        # Must be alphanumeric
        if not vin.isalnum():
            return False
        
        return True
    
    @staticmethod
    def get_validation_errors(vin: str) -> list[str]:
        """Return list of validation errors for user feedback"""
        errors = []
        
        if not vin:
            errors.append("VIN cannot be empty")
            return errors
        
        if len(vin) != 17:
            errors.append(f"VIN must be exactly 17 characters (provided: {len(vin)})")
        
        forbidden_chars = set('IOQ')
        found_forbidden = [char for char in vin.upper() if char in forbidden_chars]
        if found_forbidden:
            errors.append(f"VIN contains forbidden characters: {', '.join(found_forbidden)}")
        
        if not vin.isalnum():
            errors.append("VIN can only contain letters and numbers")
        
        return errors

class VINDecoder:
    """
    Professional VIN decoder with comprehensive error handling and validation
    """
    
    def __init__(self):
        self.base_url = "https://vpic.nhtsa.dot.gov/api/vehicles/decodevin"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AutomotiveCyberSecurityScanner/1.0',
            'Accept': 'application/json'
        })
        self.validator = VINValidator()
    
    def decode_vin(self, vin: str) -> Optional[Dict]:
        """
        Decode VIN using NHTSA API with comprehensive validation and error handling
        
        Args:
            vin: 17-character Vehicle Identification Number
            
        Returns:
            Dictionary with vehicle information or None if decoding fails
            
        Raises:
            ValueError: If VIN format is invalid
            Exception: If API call fails or response is invalid
        """
        # Clean and validate input
        clean_vin = vin.upper().strip() if vin else ""
        
        # Validate VIN format
        validation_errors = self.validator.get_validation_errors(clean_vin)
        if validation_errors:
            raise ValueError(f"Invalid VIN format: {'; '.join(validation_errors)}")
        
        logger.info(f"Decoding VIN: {clean_vin}")
        
        try:
            # Rate limiting delay for API courtesy
            time.sleep(0.5)
            
            # Make API request
            url = f"{self.base_url}/{clean_vin}?format=json"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse response
            data = response.json()
            if 'Results' not in data:
                logger.warning(f"No results in NHTSA response for VIN: {clean_vin}")
                return None
            
            # Process vehicle data
            vehicle_info = self._process_nhtsa_response(data['Results'], clean_vin)
            
            # Validate we got essential information
            if not self._validate_decoded_data(vehicle_info):
                logger.warning(f"Insufficient vehicle data decoded from VIN: {clean_vin}")
                return None
            
            logger.info(f"Successfully decoded VIN: {vehicle_info['make']} {vehicle_info['model']} {vehicle_info.get('year', 'Unknown')}")
            return vehicle_info
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error decoding VIN {clean_vin}: {str(e)}")
            raise Exception(f"Network error while decoding VIN: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response for VIN {clean_vin}: {str(e)}")
            raise Exception("Invalid response from VIN decoder service")
        except Exception as e:
            logger.error(f"Unexpected error decoding VIN {clean_vin}: {str(e)}")
            raise Exception(f"Error decoding VIN: {str(e)}")
    
    def _process_nhtsa_response(self, results: list, vin: str) -> Dict:
        """
        Process NHTSA API response into standardized vehicle information
        
        Args:
            results: List of variable-value pairs from NHTSA API
            vin: Original VIN for reference
            
        Returns:
            Dictionary with standardized vehicle information
        """
        vehicle_info = {
            'vin': vin,
            'source': 'vin'
        }
        
        # NHTSA variable mapping with priority handling
        variable_mapping = {
            'make': ['make', 'manufacturer name'],
            'model': ['model', 'series'],
            'year': ['model year', 'year'],
            'trim': ['trim', 'trim2'],
            'body_class': ['body class'],
            'engine_cylinders': ['engine number of cylinders'],
            'fuel_type': ['fuel type - primary'],
            'transmission': ['transmission style', 'transmission speeds']
        }
        
        # Process each result item
        for item in results:
            variable = item.get('Variable', '').lower()
            value = item.get('Value', '').strip()
            
            # Skip empty or null values
            if not value or value.lower() in ['null', 'not applicable', '', 'not available']:
                continue
            
            # Map variables to our standardized format
            for field, possible_vars in variable_mapping.items():
                if any(var in variable for var in possible_vars):
                    # Don't overwrite if we already have this field (priority to first match)
                    if field not in vehicle_info:
                        vehicle_info[field] = str(value)
                    break
        
        return vehicle_info
    
    def _validate_decoded_data(self, vehicle_info: Dict) -> bool:
        """
        Validate that decoded vehicle information contains essential fields
        
        Args:
            vehicle_info: Processed vehicle information dictionary
            
        Returns:
            True if vehicle data is sufficient for use
        """
        required_fields = ['make', 'model']
        return all(field in vehicle_info and vehicle_info[field] for field in required_fields)
    
    def validate_vin(self, vin: str) -> bool:
        """
        Validate VIN format
        
        Args:
            vin: VIN string to validate
            
        Returns:
            True if VIN format is valid
        """
        return self.validator.is_valid_format(vin)
    
    def get_validation_errors(self, vin: str) -> list[str]:
        """
        Get detailed validation errors for user feedback
        
        Args:
            vin: VIN string to validate
            
        Returns:
            List of validation error messages
        """
        return self.validator.get_validation_errors(vin)
