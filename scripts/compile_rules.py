import sys
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
import sigma.backends.elasticsearch as es_backend
from sigma.pipelines.sysmon import sysmon_pipeline

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT_DIR / "rules"
DIST_DIR = ROOT_DIR / "dist"

def get_elastic_backend(pipeline):
    for class_name in ["LuceneBackend", "ElasticsearchLuceneBackend", "ElasticsearchBackend"]:
        if hasattr(es_backend, class_name):
            backend_cls = getattr(es_backend, class_name)
            return backend_cls(pipeline)
    raise ImportError("Nenhum backend compativel encontrado em sigma.backends.elasticsearch")

def get_rule_stem(rule) -> str:
    """Extrai o nome base do arquivo da regra ou recorre ao UUID."""
    if hasattr(rule, "source") and rule.source:
        if hasattr(rule.source, "path") and rule.source.path:
            return Path(rule.source.path).stem
        clean_path = str(rule.source).split(":")[0]
        if clean_path and clean_path != "None":
            return Path(clean_path).stem
    return str(rule.id)

def compile_all():
    print(f"[*] Varrendo regras em: {RULES_DIR}")
    rule_files = list(RULES_DIR.glob("**/*.yml"))
    
    if not rule_files:
        print("[!] Nenhuma regra Sigma (.yml) encontrada para compilar.", file=sys.stderr)
        sys.exit(1)

    # 1. Carregar regras em memoria
    collection = SigmaCollection.load_ruleset(rule_files)
    print(f"[+] Total de regras carregadas: {len(collection)}")

    # 2. Inicializar o pipeline Sysmon
    pipeline = sysmon_pipeline()

    # 3. Mapear os backends suportados
    backends = {
        "sentinel_kql": KustoBackend(pipeline),
        "splunk_spl": SplunkBackend(pipeline),
        "elastic_lucene": get_elastic_backend(pipeline)
    }

    DIST_DIR.mkdir(exist_ok=True)

    # 4. Compilar para cada backend de destino
    for target_name, backend in backends.items():
        target_dir = DIST_DIR / target_name
        target_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[*] Compilando para backend: {target_name}...")

        for rule in collection:
            rule_stem = get_rule_stem(rule)
            try:
                queries = backend.convert_rule(rule)
                out_file = target_dir / f"{rule_stem}.txt"
                
                with open(out_file, "w", encoding="utf-8") as f:
                    for query in queries:
                        f.write(f"{query}\n")
                        
                print(f"  [OK] {rule_stem} -> dist/{target_name}/{out_file.name}")
            except Exception as e:
                print(f"  [ERRO] Falha ao compilar {rule_stem} para {target_name}: {e}", file=sys.stderr)
                sys.exit(1)

    print("\n[+] Compilacao concluida com sucesso para todos os destinos!")

if __name__ == "__main__":
    compile_all()