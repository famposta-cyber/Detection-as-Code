import uuid
import yaml
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT_DIR / "rules"

def get_sigma_rules():
    rules = list(RULES_DIR.glob("**/*.yml"))
    return rules

@pytest.mark.parametrize("rule_path", get_sigma_rules(), ids=lambda p: p.name)
def test_sigma_schema_and_metadata(rule_path):
    with open(rule_path, "r", encoding="utf-8") as f:
        try:
            rule_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            pytest.fail(f"Erro de sintaxe YAML em {rule_path.name}: {e}")

    # 1. Validar presenca de campos obrigatorios
    required_keys = [
        "title", "id", "status", "description", 
        "author", "date", "tags", "logsource", 
        "detection", "level"
    ]
    for key in required_keys:
        assert key in rule_data, f"Campo obrigatorio ausente '{key}' em {rule_path.name}"

    # 2. Validar se o ID e um UUID valido
    try:
        uuid_obj = uuid.UUID(str(rule_data["id"]), version=4)
    except ValueError:
        pytest.fail(f"O campo 'id' em {rule_path.name} precisa ser um UUIDv4 valido")

    # 3. Validar padronizacao das tags MITRE ATT&CK
    tags = rule_data.get("tags", [])
    assert isinstance(tags, list), f"Tags em {rule_path.name} devem ser uma lista"
    attack_techniques = [t for t in tags if t.startswith("attack.t")]
    assert len(attack_techniques) > 0, (
        f"A regra {rule_path.name} deve conter pelo menos uma tag de tecnica MITRE (ex: attack.t1105)"
    )

    # 4. Validar estrutura basica de deteccao
    detection = rule_data.get("detection", {})
    assert "condition" in detection, f"Bloco de deteccao em {rule_path.name} precisa ter o campo 'condition'"