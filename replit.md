# Automotive Cybersecurity Scanner

## Overview

This is a Streamlit-based web application that provides cybersecurity vulnerability scanning for automotive vehicles. The application allows users to input vehicle information either through VIN decoding or manual make/model selection, then searches for relevant Common Vulnerabilities and Exposures (CVEs) using the National Vulnerability Database (NVD) API.

The application is designed for educational and research purposes, providing general vulnerability indicators rather than precise assessments. It serves as a proof-of-concept for automotive cybersecurity research and awareness.

## System Architecture

### Frontend Architecture
- **Framework**: Streamlit web framework for rapid prototyping and deployment
- **Design Pattern**: Single-page application with expandable sections and radio button navigation
- **User Interface**: Clean, responsive web interface with warning disclaimers and input validation
- **Caching Strategy**: Streamlit's `@st.cache_resource` decorator for service initialization

### Backend Architecture
- **Language**: Python 3.11
- **Architecture Pattern**: Service-oriented with separate modules for different functionalities
- **API Integration**: RESTful API consumption using requests library
- **Data Processing**: Pandas for data manipulation and JSON for API response handling

### Core Services
1. **VIN Decoder Service** (`vin_decoder.py`): Interfaces with NHTSA API for VIN-to-vehicle-info conversion
2. **CVE Search Service** (`cve_search.py`): Queries NVD API for vulnerability information
3. **Car Data Service** (`car_data.py`): Static database of automotive makes and models

## Key Components

### VIN Decoder (`vin_decoder.py`)
- **Purpose**: Converts 17-character VINs to structured vehicle information
- **API**: NHTSA (National Highway Traffic Safety Administration) VIN Decoder API
- **Features**: Input validation, rate limiting, error handling
- **Output**: Make, model, year, and additional vehicle specifications

### CVE Searcher (`cve_search.py`)
- **Purpose**: Searches for automotive-related vulnerabilities
- **API**: NVD (National Vulnerability Database) API v2.0
- **Search Strategy**: Keyword-based queries using automotive-specific terms
- **Features**: Rate limiting, multiple search queries, result aggregation

### Car Data (`car_data.py`)
- **Purpose**: Provides manual vehicle selection capabilities
- **Data Structure**: Dictionary mapping makes to model arrays
- **Coverage**: Major automotive manufacturers and popular models
- **Use Case**: Alternative input method when VIN is unavailable

### Main Application (`app.py`)
- **Purpose**: Orchestrates user interface and service integration
- **Features**: 
  - Dual input methods (VIN or manual selection)
  - Comprehensive disclaimers and warnings
  - Result presentation and filtering
  - Error handling and user feedback

## Data Flow

1. **User Input**: User selects input method (VIN or manual selection)
2. **Vehicle Identification**: 
   - VIN path: VIN → NHTSA API → Vehicle details
   - Manual path: User selection → Static car database
3. **Vulnerability Search**: Vehicle details → NVD API → CVE results
4. **Result Processing**: Raw CVE data → Filtered and formatted results
5. **Presentation**: Processed results → Streamlit UI → User display

## External Dependencies

### APIs
- **NHTSA VIN Decoder API**: Free public API for VIN decoding
  - Rate limits: Automated traffic controls
  - Authentication: None required
  - Format: JSON responses

- **NVD API v2.0**: National Vulnerability Database API
  - Rate limits: Applied per API guidelines
  - Authentication: None required (public access)
  - Format: JSON responses with CVE details

### Python Packages
- **Core Dependencies**:
  - `streamlit>=1.46.0`: Web application framework
  - `pandas>=2.3.0`: Data manipulation and analysis
  - `requests>=2.32.4`: HTTP client for API consumption
  - `trafilatura>=2.0.0`: Text extraction (likely for future features)

## Deployment Strategy

### Platform
- **Target**: Replit autoscale deployment
- **Runtime**: Python 3.11 with Nix package management
- **Port Configuration**: Streamlit server on port 5000

### Configuration
- **Deployment Target**: Autoscale for automatic resource management
- **Run Command**: `streamlit run app.py --server.port 5000`
- **Workflow**: Parallel execution with shell command task

### Environment
- **Nix Channel**: stable-24_05 for reproducible builds
- **Locale Support**: glibcLocales package for internationalization
- **Server Configuration**: Headless mode with public address binding

## Changelog

Changelog:
- June 18, 2025. Initial setup

## User Preferences

Preferred communication style: Simple, everyday language.