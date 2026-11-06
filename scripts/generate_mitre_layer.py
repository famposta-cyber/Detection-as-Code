import json
import yaml
from pathlib import Path
from collections import defaultdict

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT_DIR / "rules"
OUTPUT_LAYER = ROOT_DIR / "mitre_coverage_layer.json"

def generate_layer():
    print(f"[*] Analisando regras em: {RULES_DIR}")
    technique_to_rules = defaultdict(list)

    for rule_file in RULES_DIR.glob("**/*.yml"):
        with open(rule_file, "r", encoding="utf-8-sig") as f:
            try:
                rule_data = yaml.safe_load(f)
            except Exception as e:
                print(f"[!] Erro ao ler {rule_file.name}: {e}")
                continue

            tags = rule_data.get("tags", [])
            rule_title = rule_data.get("title", rule_file.stem)

            for tag in tags:
                if tag.startswith("attack.t"):
                    # Normaliza attack.t1105 -> T1105 / attack.t1059.001 -> T1059.001
                    tech_id = tag.replace("attack.", "").upper()
                    technique_to_rules[tech_id].append(rule_title)

    techniques_list = []
    max_coverage = max([len(rules) for rules in technique_to_rules.values()]) if technique_to_rules else 1

    for tech_id, matched_rules in technique_to_rules.items():
        count = len(matched_rules)
        techniques_list.append({
            "techniqueID": tech_id,
            "score": count,
            "comment": f"Regras ativas ({count}): " + ", ".join(matched_rules),
            "enabled": True
        })

    layer_payload = {
        "name": "SOC Detection-as-Code Coverage",
        "versions": {
            "attack": "15",
            "navigator": "5.0.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Camada de cobertura gerada automaticamente pelo pipeline de Detection Engineering",
        "gradient": {
            "colors": ["#d1e5f0", "#67a9cf", "#2166ac"],
            "minValue": 1,
            "maxValue": max_coverage
        },
        "techniques": techniques_list
    }

    with open(OUTPUT_LAYER, "w", encoding="utf-8") as f:
        json.dump(layer_payload, f, indent=2, ensure_ascii=False)

    print(f"[+] Layer ATT&CK gerado com sucesso: {OUTPUT_LAYER}")
    print(f"[+] Total de tecnicas mapeadas: {len(techniques_list)}")
    for tech_id, rules in technique_to_rules.items():
        print(f"    - {tech_id}: {len(rules)} regra(s) -> {', '.join(rules)}")

if __name__ == "__main__":
    generate_layer()