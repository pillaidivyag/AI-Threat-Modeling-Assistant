import re
import json
import ollama
from validators import validate_ai_output

def sanitize_input(description: str) -> str:
    injection_patterns = [
        r"(ignore previous instructions|disregard all prior rules)",
        r"(you are now|act as an unrestricted)",
        r"(system prompt:|print system instructions)"
    ]
    cleaned_text = description
    for pattern in injection_patterns:
        if re.search(pattern, cleaned_text, re.IGNORECASE):
            cleaned_text = re.sub(pattern, "[REDACTED_SUSPICIOUS_INPUT]", cleaned_text, flags=re.IGNORECASE)
    return cleaned_text.strip()

def calculate_risk(threats: list) -> list:
    score_map = {"Low": 1, "Medium": 2, "High": 3}
    for threat in threats:
        l_str = threat.get("likelihood", "Medium")
        i_str = threat.get("impact", "Medium")
        l_val = score_map.get(l_str, 2)
        i_val = score_map.get(i_str, 2)
        
        product = l_val * i_val
        if product >= 6:
            risk_level = "High"
        elif product >= 3:
            risk_level = "Medium"
        else:
            risk_level = "Low"
            
        threat["calculated_risk_score"] = product
        threat["risk_level"] = risk_level
    return threats

def generate_reports(data: dict):
    with open("threat-model.json", "w") as f:
        json.dump(data, f, indent=4)
        
    md_lines = [
        "# Threat Model Report",
        "\n## Summary",
        f"Total Identified Threats: {len(data['threats'])}",
        "\n## Identified Threats\n"
    ]
    
    for t in data["threats"]:
        md_lines.append(f"### [{t['id']}] {t['title']}")
        md_lines.append(f"- **STRIDE Category:** {t['stride_category']}")
        md_lines.append(f"- **Risk Level:** {t['risk_level']} (Score: {t['calculated_risk_score']})")
        md_lines.append(f"- **Description:** {t['description']}\n")
        
    with open("threat-model.md", "w") as f:
        f.write("\n".join(md_lines))

def run_threat_modelling_pipeline(app_description: str, model_name: str = "qwen3:4b-instruct"):
    print("[*] Sanitizing input description...")
    safe_input = sanitize_input(app_description)
    
    print("[*] Querying local Ollama model for STRIDE analysis...")
    system_prompt = (
        "You are an expert cybersecurity threat modeler. "
        "Analyze the following application architecture description using the STRIDE methodology "
        "(Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). "
        "Output your response strictly as valid JSON matching this structure: "
        "{\"threats\": [{\"id\": \"T1\", \"title\": \"...\", \"stride_category\": \"Spoofing\", \"description\": \"...\", \"likelihood\": \"High\", \"impact\": \"High\"}]}"
    )
    
    response = ollama.chat(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": safe_input}
        ],
        options={"temperature": 0.2}
    )
    
    # Corrected attribute access for ChatResponse object
    raw_content = response.message.content
    
    print("[*] Validating AI output against strict schema and STRIDE rules...")
    validated_data = validate_ai_output(raw_content)
    
    print("[*] Running Deterministic Risk Engine...")
    validated_data["threats"] = calculate_risk(validated_data["threats"])
    
    print("[*] Writing final outputs...")
    generate_reports(validated_data)
    print("[+] Pipeline complete! Generated threat-model.json and threat-model.md.")