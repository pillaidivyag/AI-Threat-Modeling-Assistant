import json

def validate_ai_output(raw_output: str) -> dict:
    """
    Validates JSON format, required schema fields, STRIDE categories, 
    and ensures threats are actually returned.
    """
    # 1. JSON validation
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON response from AI: {e}")
        
    # 2. Required fields validation
    if "threats" not in data or not isinstance(data["threats"], list):
        raise ValueError("Missing 'threats' list in AI response schema.")
        
    threats = data["threats"]
    
    # 3. Threat count validation
    if len(threats) == 0:
        raise ValueError("Threat count validation failed: No threats returned.")
        
    valid_stride = {
        "Spoofing", "Tampering", "Repudiation", 
        "Information Disclosure", "Denial of Service", "Elevation of Privilege"
    }
    
    for idx, threat in enumerate(threats):
        required_keys = {"id", "title", "stride_category", "description", "likelihood", "impact"}
        if not required_keys.issubset(threat.keys()):
            raise ValueError(f"Threat at index {idx} is missing required fields.")
            
        # 4. STRIDE category validation
        if threat["stride_category"] not in valid_stride:
            raise ValueError(f"Invalid STRIDE category '{threat['stride_category']}' at index {idx}.")
            
    return data