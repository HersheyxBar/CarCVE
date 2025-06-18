import streamlit as st
import pandas as pd
from vin_decoder import VINDecoder
from cve_search import CVESearcher
from car_data import CAR_MAKES_MODELS
import time

# Page configuration
st.set_page_config(
    page_title="Automotive Cybersecurity Scanner",
    page_icon="🚗",
    layout="wide"
)

# Initialize services
@st.cache_resource
def get_vin_decoder():
    return VINDecoder()

@st.cache_resource
def get_cve_searcher():
    return CVESearcher()

vin_decoder = get_vin_decoder()
cve_searcher = get_cve_searcher()

# Main app
def main():
    st.title("🚗 Automotive Cybersecurity Scanner")
    st.markdown("---")
    
    # Disclaimer section
    with st.expander("⚠️ Important Disclaimers - Please Read", expanded=False):
        st.warning("""
        **Data Limitations & Legal Notice:**
        
        - This tool provides general vulnerability indicators, not precise vulnerability assessments
        - CVE searches are keyword-based and may return false positives or miss relevant vulnerabilities
        - Firmware version information cannot be determined from VIN alone
        - Results should be verified with official manufacturer sources
        - This tool is for educational and research purposes only
        - No warranty is provided for the accuracy or completeness of results
        - Vehicle data privacy laws may apply - use responsibly
        """)
    
    # Input method selection
    st.subheader("🔍 Select Vehicle Information Method")
    input_method = st.radio(
        "Choose how to specify the vehicle:",
        ["Select Make & Model", "Enter VIN Number"],
        horizontal=True
    )
    
    vehicle_info = None
    
    if input_method == "Select Make & Model":
        vehicle_info = handle_make_model_selection()
    else:
        vehicle_info = handle_vin_input()
    
    if vehicle_info:
        st.markdown("---")
        display_vehicle_info(vehicle_info)
        search_vulnerabilities(vehicle_info)

def handle_make_model_selection():
    """Handle manual make and model selection"""
    col1, col2, col3 = st.columns(3)
    
    with col1:
        make = st.selectbox(
            "Select Make:",
            options=[""] + list(CAR_MAKES_MODELS.keys()),
            index=0
        )
    
    model = None
    year = None
    
    if make:
        with col2:
            models = CAR_MAKES_MODELS.get(make, [])
            model = st.selectbox(
                "Select Model:",
                options=[""] + models,
                index=0
            )
        
        if model:
            with col3:
                # Year range from 2010 to current year + 1
                current_year = 2025
                years = list(range(2010, current_year + 2))
                year = st.selectbox(
                    "Select Year:",
                    options=[""] + years,
                    index=0
                )
    
    if make and model and year:
        return {
            'make': make,
            'model': model,
            'year': str(year),
            'source': 'manual'
        }
    
    return None

def handle_vin_input():
    """Handle VIN input and decoding"""
    st.subheader("Enter VIN Number")
    vin = st.text_input(
        "VIN (17 characters):",
        max_chars=17,
        help="Enter the 17-character Vehicle Identification Number"
    ).upper().strip()
    
    if vin:
        if len(vin) != 17:
            st.error("VIN must be exactly 17 characters long")
            return None
        
        if not vin.isalnum():
            st.error("VIN should contain only letters and numbers")
            return None
        
        with st.spinner("Decoding VIN..."):
            try:
                vehicle_info = vin_decoder.decode_vin(vin)
                if vehicle_info:
                    st.success("VIN decoded successfully!")
                    return vehicle_info
                else:
                    st.error("Could not decode VIN. Please check the VIN and try again.")
                    return None
            except Exception as e:
                st.error(f"Error decoding VIN: {str(e)}")
                return None
    
    return None

def display_vehicle_info(vehicle_info):
    """Display decoded vehicle information"""
    st.subheader("🚙 Vehicle Information")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Make", vehicle_info.get('make', 'Unknown'))
    
    with col2:
        st.metric("Model", vehicle_info.get('model', 'Unknown'))
    
    with col3:
        st.metric("Year", vehicle_info.get('year', 'Unknown'))
    
    with col4:
        source = "VIN Decode" if vehicle_info.get('source') == 'vin' else "Manual Selection"
        st.metric("Source", source)

def search_vulnerabilities(vehicle_info):
    """Search for vulnerabilities based on vehicle information"""
    st.subheader("🔍 CVE Vulnerability Search")
    
    # Search options
    col1, col2 = st.columns(2)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity:",
            options=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default=["MEDIUM", "HIGH", "CRITICAL"]
        )
    
    with col2:
        max_results = st.slider(
            "Maximum Results:",
            min_value=10,
            max_value=100,
            value=50,
            step=10
        )
    
    if st.button("🔍 Search for Vulnerabilities", type="primary"):
        with st.spinner("Searching CVE database..."):
            try:
                # Add rate limiting delay
                time.sleep(1)
                
                results = cve_searcher.search_vehicle_cves(
                    vehicle_info['make'],
                    vehicle_info['model'],
                    vehicle_info.get('year'),
                    max_results=max_results
                )
                
                if results:
                    display_cve_results(results, severity_filter)
                else:
                    st.info("No specific CVEs found for this vehicle. This doesn't mean the vehicle is secure - it may indicate limited public vulnerability data.")
                    
            except Exception as e:
                st.error(f"Error searching CVEs: {str(e)}")

def display_cve_results(results, severity_filter):
    """Display CVE search results"""
    st.subheader("📋 Vulnerability Results")
    
    # Filter results by severity
    filtered_results = []
    for result in results:
        severity = result.get('severity', 'UNKNOWN').upper()
        if not severity_filter or severity in severity_filter:
            filtered_results.append(result)
    
    if not filtered_results:
        st.warning("No results match the selected severity filters.")
        return
    
    st.info(f"Found {len(filtered_results)} vulnerabilities matching your criteria")
    
    # Display results
    for i, cve in enumerate(filtered_results):
        with st.expander(f"🚨 {cve['id']} - {cve.get('severity', 'Unknown')} Severity"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.write("**Description:**")
                st.write(cve.get('description', 'No description available'))
                
                if cve.get('published_date'):
                    st.write(f"**Published:** {cve['published_date']}")
                
                if cve.get('modified_date'):
                    st.write(f"**Last Modified:** {cve['modified_date']}")
                
                if cve.get('references'):
                    st.write("**References:**")
                    for ref in cve['references'][:3]:  # Limit to first 3 references
                        st.write(f"- {ref}")
            
            with col2:
                # Severity badge
                severity = cve.get('severity', 'UNKNOWN')
                if severity == 'CRITICAL':
                    st.error(f"🔴 {severity}")
                elif severity == 'HIGH':
                    st.warning(f"🟠 {severity}")
                elif severity == 'MEDIUM':
                    st.info(f"🟡 {severity}")
                else:
                    st.info(f"⚪ {severity}")
                
                # CVSS Score if available
                if cve.get('cvss_score'):
                    st.metric("CVSS Score", f"{cve['cvss_score']}/10")
    
    # Additional information
    with st.expander("ℹ️ How to Interpret These Results"):
        st.write("""
        **Understanding the Results:**
        
        - **Keyword Matching**: Results are found by searching for your vehicle's make, model, and automotive terms
        - **Relevance**: Not all CVEs may directly apply to your specific vehicle configuration
        - **Verification**: Always verify vulnerabilities with official manufacturer sources
        - **False Positives**: Some results may be for different products with similar names
        
        **Next Steps:**
        - Contact your vehicle manufacturer for official vulnerability information
        - Check for available software/firmware updates
        - Consult with automotive cybersecurity professionals for detailed assessments
        """)

if __name__ == "__main__":
    main()
