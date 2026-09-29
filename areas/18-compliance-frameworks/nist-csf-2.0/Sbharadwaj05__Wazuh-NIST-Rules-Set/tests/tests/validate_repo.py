import json
import os
import re
import xml.etree.ElementTree as ET

def validate():
    print("==================================================")
    print("[INFO] REPOSITORY INTEGRITY VALIDATION RUN")
    print("==================================================")
    
    # 1. Parse JSON Mappings
    with open("mappings/nist-csf-mitre-wazuh.json", "r", encoding="utf-8") as f:
        mapping_data = json.load(f)
    
    mapped_rule_ids = {m["wazuh_rule_id"] for m in mapping_data["mappings"]}
    print(f"[OK] Parsed {len(mapped_rule_ids)} rules from mappings/nist-csf-mitre-wazuh.json")
    
    # 2. Parse XML Rules
    xml_rules = {}
    rules_dir = "rules"
    for root_dir, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".xml"):
                path = os.path.join(root_dir, file)
                try:
                    tree = ET.parse(path)
                    root = tree.getroot()
                    # Find all rules
                    for rule in root.findall(".//rule"):
                        rule_id = rule.get("id")
                        if rule_id:
                            if rule_id in xml_rules:
                                print(f"[ERROR] Duplicate XML Rule ID found: {rule_id} in {path} and {xml_rules[rule_id]['path']}")
                            xml_rules[rule_id] = {
                                "id": rule_id,
                                "level": rule.get("level"),
                                "path": path,
                                "name": rule.findtext("description", "No description"),
                                "no_log": "no_log" in (rule.findtext("options") or "")
                            }
                except Exception as e:
                    print(f"[ERROR] Failed to parse XML file {path}: {e}")
                    
    print(f"[OK] Found {len(xml_rules)} total rules across XML files.")
    
    # 3. Check for silent helpers
    alerting_xml_rules = {rid: r for rid, r in xml_rules.items() if int(r["level"]) > 0 and not r["no_log"]}
    silent_helpers = {rid: r for rid, r in xml_rules.items() if int(r["level"]) == 0 or r["no_log"]}
    print(f"   - Alerting Rules: {len(alerting_xml_rules)}")
    print(f"   - Silent Helper Rules: {len(silent_helpers)} (IDs: {', '.join(silent_helpers.keys())})")
    
    # 4. JSON vs XML Alignment
    print("\n--- Checking Mappings vs XML ---")
    missing_xml = mapped_rule_ids - xml_rules.keys()
    if missing_xml:
        print(f"[ERROR] Rules in JSON mapping but NOT in XML: {missing_xml}")
    else:
        print("[OK] All mapped rule IDs exist in XML rules.")
        
    missing_mapping = alerting_xml_rules.keys() - mapped_rule_ids
    if missing_mapping:
        print(f"[ERROR] Alerting XML rules NOT in JSON mapping: {missing_mapping}")
    else:
        print("[OK] All alerting XML rules are mapped in JSON.")

    # 5. README check
    print("\n--- Checking README.md ---")
    with open("README.md", "r", encoding="utf-8") as f:
        readme_content = f.read()
        
    # Extract IDs from README table
    readme_ids = set(re.findall(r'\|\s*(1000\d{2})\s*\|', readme_content))
    print(f"[OK] Found {len(readme_ids)} rule IDs in README.md")
    
    readme_missing = mapped_rule_ids - readme_ids
    if readme_missing:
        print(f"[ERROR] Mapped rule IDs missing from README: {readme_missing}")
    else:
        print("[OK] All mapped rule IDs are documented in README.")
        
    readme_extra = readme_ids - mapped_rule_ids
    if readme_extra:
        print(f"[ERROR] Extra rule IDs in README not in mapping: {readme_extra}")
    else:
        print("[OK] No phantom or extra rules in README.")
        
    # Check for duplicate tables in README
    if readme_content.count("### Detailed Rule Mapping") > 1:
        print("[ERROR] Duplicate 'Detailed Rule Mapping' headers in README.md")
    else:
        print("[OK] No duplicate mapping headers in README.md")

    # 6. Rule Catalog check
    print("\n--- Checking Rule Catalog ---")
    with open("docs/rule-catalog.md", "r", encoding="utf-8") as f:
        catalog_content = f.read()
        
    catalog_ids = set(re.findall(r'### Rule (1000\d{2})', catalog_content))
    print(f"[OK] Found {len(catalog_ids)} rule IDs in rule-catalog.md")
    
    catalog_missing = mapped_rule_ids - catalog_ids
    if catalog_missing:
        print(f"[ERROR] Mapped rule IDs missing from Rule Catalog: {catalog_missing}")
    else:
        print("[OK] All mapped rules are documented in Rule Catalog.")
        
    catalog_extra = catalog_ids - mapped_rule_ids
    if catalog_extra:
        print(f"[ERROR] Extra rule IDs in Rule Catalog: {catalog_extra}")
    else:
        print("[OK] No extra rules in Rule Catalog.")

    print("\n==================================================")
    print("[SUCCESS] VALIDATION COMPLETE!")
    print("==================================================")

if __name__ == "__main__":
    validate()
