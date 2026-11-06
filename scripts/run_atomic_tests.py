import sys
import subprocess
from pathlib import Path

def run_atomic_test(technique_id: str, test_number: int = 1) -> bool:
    print(f'[*] Disparando Atomic Red Team para tecnica: {technique_id} (Teste #{test_number})')
    
    # Comando PowerShell headless para carregar o modulo e rodar a simulacao
    ps_cmd = (
        f'Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force -ErrorAction SilentlyContinue; '
        f'Invoke-AtomicTest {technique_id} -TestNumbers {test_number} -Confirm:$false'
    )
    
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
            capture_output=True,
            text=True,
            timeout=120
        )
        if proc.returncode != 0:
            print(f'[!] Falha na execucao do Atomic Test {technique_id}:\n{proc.stderr}', file=sys.stderr)
            return False
            
        print(f'[+] Simulacao da tecnica {technique_id} concluida com sucesso.')
        return True
    except FileNotFoundError:
        print('[!] PowerShell nao disponivel no PATH ou runner nao compativel.', file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f'[!] Timeout ao executar o teste da tecnica {technique_id}.', file=sys.stderr)
        return False

if __name__ == '__main__':
    # Exemplo validando a tecnica T1105 (Ingress Tool Transfer / Certutil)
    technique = sys.argv[1] if len(sys.argv) > 1 else 'T1105'
    success = run_atomic_test(technique)
    sys.exit(0 if success else 1)
