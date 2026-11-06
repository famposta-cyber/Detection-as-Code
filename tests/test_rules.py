import json
import uuid
import yaml
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT_DIR / "rules"
TELEMETRY_DIR = ROOT_DIR / "tests" / "telemetry"

def get_sigma_rules():
    return list(RULES_DIR.glob("**/*.yml"))

# --- 1. TESTE DE LINTING / SCHEMA ---
@pytest.mark.parametrize("rule_path", get_sigma_rules(), ids=lambda p: p.name)
def test_sigma_schema_and_metadata(rule_path):
    with open(rule_path, "r", encoding="utf-8-sig") as f:
        try:
            rule_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            pytest.fail(f"Erro de sintaxe YAML em {rule_path.name}: {e}")

    required_keys = [
        "title", "id", "status", "description", 
        "author", "date", "tags", "logsource", 
        "detection", "level"
    ]
    for key in required_keys:
        assert key in rule_data, f"Campo obrigatorio ausente '{key}' em {rule_path.name}"

    try:
        uuid.UUID(str(rule_data["id"]), version=4)
    except ValueError:
        pytest.fail(f"O campo 'id' em {rule_path.name} precisa ser um UUIDv4 valido")

    tags = rule_data.get("tags", [])
    assert isinstance(tags, list), f"Tags em {rule_path.name} devem ser uma lista"
    attack_techniques = [t for t in tags if t.startswith("attack.t")]
    assert len(attack_techniques) > 0, (
        f"A regra {rule_path.name} deve conter pelo menos uma tag de tecnica MITRE (ex: attack.t1105)"
    )

    detection = rule_data.get("detection", {})
    assert "condition" in detection, f"Bloco de deteccao em {rule_path.name} precisa ter o campo 'condition'"

# --- 2. TESTE FUNCIONAL DE DETECCAO (TP vs FP) ---
def test_certutil_detection_against_telemetry():
    tp_file = TELEMETRY_DIR / "certutil_download_tp.json"
    fp_file = TELEMETRY_DIR / "certutil_benign_fp.json"

    assert tp_file.exists(), "Dataset True Positive ausente em tests/telemetry/"
    assert fp_file.exists(), "Dataset False Positive ausente em tests/telemetry/"

    # encoding="utf-8-sig" elimina o caractere BOM \ufeff de forma transparente
    with open(tp_file, "r", encoding="utf-8-sig") as f:
        tp_event = json.load(f)
    with open(fp_file, "r", encoding="utf-8-sig") as f:
        fp_event = json.load(f)

    def evaluate_certutil_rule(event: dict) -> bool:
        image = event.get("Image", "").lower()
        original_name = event.get("OriginalFileName", "")
        cmd = event.get("CommandLine", "")

        selection_img = image.endswith(r"\certutil.exe") or original_name == "CertUtil.exe"
        
        target_flags = [" -urlcache ", " /urlcache ", " -split ", " /split "]
        selection_flags = any(flag in cmd for flag in target_flags)

        return selection_img and selection_flags

    assert evaluate_certutil_rule(tp_event) is True, (
        "FALHA DE DETECCAO: A regra nao alertou sobre o evento True Positive!"
    )

    assert evaluate_certutil_rule(fp_event) is False, (
        "FALSO POSITIVO: A regra disparou indevidamente contra um evento benigno!"
    )