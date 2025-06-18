"""
Car makes and models data for manual selection
This is a simplified dataset of common automotive manufacturers and their popular models
"""

CAR_MAKES_MODELS = {
    "Acura": [
        "ILX", "TLX", "RLX", "MDX", "RDX", "NSX", "Integra"
    ],
    "Audi": [
        "A3", "A4", "A5", "A6", "A7", "A8", "Q3", "Q5", "Q7", "Q8", 
        "TT", "R8", "e-tron", "RS3", "RS4", "RS5", "RS6", "RS7"
    ],
    "BMW": [
        "1 Series", "2 Series", "3 Series", "4 Series", "5 Series", "6 Series", "7 Series", "8 Series",
        "X1", "X2", "X3", "X4", "X5", "X6", "X7", "Z4", "i3", "i4", "iX"
    ],
    "Buick": [
        "Encore", "Encore GX", "Envision", "Enclave", "Regal", "LaCrosse"
    ],
    "Cadillac": [
        "ATS", "CTS", "CT4", "CT5", "CT6", "XT4", "XT5", "XT6", "Escalade", "Lyriq"
    ],
    "Chevrolet": [
        "Spark", "Sonic", "Cruze", "Malibu", "Impala", "Camaro", "Corvette",
        "Trax", "Equinox", "Blazer", "Traverse", "Tahoe", "Suburban",
        "Colorado", "Silverado", "Bolt EV", "Bolt EUV"
    ],
    "Chrysler": [
        "300", "Pacifica", "Voyager"
    ],
    "Dodge": [
        "Charger", "Challenger", "Durango", "Journey", "Grand Caravan"
    ],
    "Ford": [
        "Fiesta", "Focus", "Fusion", "Mustang", "Taurus",
        "EcoSport", "Escape", "Edge", "Explorer", "Expedition",
        "Ranger", "F-150", "F-250", "F-350", "Bronco", "Maverick",
        "Mustang Mach-E", "F-150 Lightning"
    ],
    "Genesis": [
        "G70", "G80", "G90", "GV70", "GV80"
    ],
    "GMC": [
        "Terrain", "Acadia", "Yukon", "Canyon", "Sierra", "Hummer EV"
    ],
    "Honda": [
        "Fit", "Civic", "Insight", "Accord", "HR-V", "CR-V", "Passport", "Pilot",
        "Ridgeline", "Clarity", "Odyssey"
    ],
    "Hyundai": [
        "Accent", "Elantra", "Sonata", "Azera", "Veloster",
        "Venue", "Kona", "Tucson", "Santa Fe", "Palisade",
        "Ioniq", "Ioniq 5", "Nexo"
    ],
    "Infiniti": [
        "Q50", "Q60", "Q70", "QX30", "QX50", "QX60", "QX80"
    ],
    "Jaguar": [
        "XE", "XF", "XJ", "F-TYPE", "E-PACE", "F-PACE", "I-PACE"
    ],
    "Jeep": [
        "Renegade", "Compass", "Cherokee", "Grand Cherokee", "Wrangler", "Gladiator"
    ],
    "Kia": [
        "Rio", "Forte", "Optima", "Stinger", "Soul", "Seltos", "Sportage", "Sorento", "Telluride",
        "Niro", "EV6"
    ],
    "Land Rover": [
        "Discovery Sport", "Discovery", "Range Rover Evoque", "Range Rover Velar", 
        "Range Rover Sport", "Range Rover", "Defender"
    ],
    "Lexus": [
        "IS", "ES", "GS", "LS", "RC", "LC", "UX", "NX", "GX", "LX", "RX"
    ],
    "Lincoln": [
        "MKZ", "Continental", "Corsair", "Nautilus", "Aviator", "Navigator"
    ],
    "Mazda": [
        "Mazda3", "Mazda6", "MX-5 Miata", "CX-3", "CX-30", "CX-5", "CX-9", "MX-30"
    ],
    "Mercedes-Benz": [
        "A-Class", "C-Class", "E-Class", "S-Class", "CLA", "CLS", "G-Class",
        "GLA", "GLB", "GLC", "GLE", "GLS", "SLC", "SL", "AMG GT", "EQS", "EQE"
    ],
    "Mini": [
        "Cooper", "Cooper Countryman", "Cooper Clubman"
    ],
    "Mitsubishi": [
        "Mirage", "Lancer", "Eclipse Cross", "Outlander", "Outlander Sport"
    ],
    "Nissan": [
        "Versa", "Sentra", "Altima", "Maxima", "370Z", "GT-R",
        "Kicks", "Rogue Sport", "Rogue", "Murano", "Pathfinder", "Armada",
        "Frontier", "Titan", "Leaf", "Ariya"
    ],
    "Porsche": [
        "718 Boxster", "718 Cayman", "911", "Panamera", "Macan", "Cayenne", "Taycan"
    ],
    "Ram": [
        "1500", "2500", "3500", "ProMaster", "ProMaster City"
    ],
    "Subaru": [
        "Impreza", "Legacy", "Outback", "Forester", "Crosstrek", "Ascent", "WRX", "BRZ"
    ],
    "Tesla": [
        "Model S", "Model 3", "Model X", "Model Y", "Cybertruck", "Roadster"
    ],
    "Toyota": [
        "Yaris", "Corolla", "Camry", "Avalon", "86", "Supra",
        "C-HR", "RAV4", "Venza", "Highlander", "4Runner", "Sequoia", "Land Cruiser",
        "Tacoma", "Tundra", "Prius", "Mirai", "Sienna"
    ],
    "Volkswagen": [
        "Jetta", "Passat", "Arteon", "Golf", "GTI", "Tiguan", "Atlas", "ID.4"
    ],
    "Volvo": [
        "S60", "S90", "V60", "V90", "XC40", "XC60", "XC90", "C40", "XC40 Recharge"
    ]
}

# Additional utility functions for car data
def get_all_makes():
    """Return sorted list of all car makes"""
    return sorted(CAR_MAKES_MODELS.keys())

def get_models_for_make(make):
    """Return sorted list of models for a given make"""
    return sorted(CAR_MAKES_MODELS.get(make, []))

def search_makes(query):
    """Search for makes containing the query string"""
    query = query.lower()
    return [make for make in CAR_MAKES_MODELS.keys() if query in make.lower()]

def search_models(make, query):
    """Search for models within a make containing the query string"""
    if make not in CAR_MAKES_MODELS:
        return []
    
    query = query.lower()
    models = CAR_MAKES_MODELS[make]
    return [model for model in models if query in model.lower()]
