import requests
import json
import time
from typing import Dict, Optional

class VINDecoder:
    """
    VIN decoder using NHTSA API
    """
    
    def __init__(self):
        self.base_url = "https://vpic.nhtsa.dot.gov/api/vehicles/decodevin"
        self.session = requests.Session()
        # Set timeout and headers
        self.session.headers.update({
            'User-Agent': 'AutomotiveCyberSecurityScanner/1.0'
        })
    
    def decode_vin(self, vin: str) -> Optional[Dict]:
        """
        Decode VIN using NHTSA API
        
        Args:
            vin (str): 17-character VIN
            
        Returns:
            Dict with vehicle information or None if failed
        """
        if not vin or len(vin) != 17:
            raise ValueError("VIN must be exactly 17 characters")
        
        # Clean VIN
        vin = vin.upper().strip()
        
        try:
            # Add delay for rate limiting
            time.sleep(0.5)
            
            url = f"{self.base_url}/{vin}?format=json"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'Results' not in data:
                return None
            
            results = data['Results']
            
            # Extract relevant information
            vehicle_info = {
                'vin': vin,
                'source': 'vin'
            }
            
            # Parse results into a more usable format
            for item in results:
                variable = item.get('Variable', '').lower()
                value = item.get('Value', '')
                
                # Skip empty values or null
                if not value or value.lower() in ['null', 'not applicable', '']:
                    continue
                
                # Map NHTSA variables to our format
                if 'make' in variable:
                    vehicle_info['make'] = value
                elif 'model' in variable and 'year' not in variable:
                    vehicle_info['model'] = value
                elif 'model year' in variable or variable == 'year':
                    vehicle_info['year'] = str(value)
                elif 'manufacturer' in variable and 'make' not in vehicle_info:
                    vehicle_info['make'] = value
                elif 'series' in variable and 'model' not in vehicle_info:
                    vehicle_info['model'] = value
                elif 'trim' in variable:
                    vehicle_info['trim'] = value
                elif 'body class' in variable:
                    vehicle_info['body_class'] = value
                elif 'engine' in variable and 'cylinders' in variable:
                    vehicle_info['engine_cylinders'] = value
                elif 'fuel type' in variable:
                    vehicle_info['fuel_type'] = value
                elif 'transmission' in variable:
                    vehicle_info['transmission'] = value
            
            # Validate that we got essential information
            if not all(key in vehicle_info for key in ['make', 'model']):
                return None
            
            return vehicle_info
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error while decoding VIN: {str(e)}")
        except json.JSONDecodeError:
            raise Exception("Invalid response from VIN decoder service")
        except Exception as e:
            raise Exception(f"Error decoding VIN: {str(e)}")
    
    def validate_vin(self, vin: str) -> bool:
        """
        Basic VIN validation
        
        Args:
            vin (str): VIN to validate
            
        Returns:
            bool: True if VIN appears valid
        """
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
