#!/usr/bin/env python3
# MB Inspector v0.3.1
# Inventário e auditoria básica de rede.
# Use somente em redes/equipamentos para os quais você tem autorização.

import argparse
import csv
import datetime
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "mb_inspector_data"
DATA_DIR.mkdir(exist_ok=True)

# Portas comuns em CFTV
CAMERA_PORTS = [
    80, 443, 554, 8000, 8080, 8443, 8554,
    8899, 37777, 37778, 34567, 5000
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 443, 445,
    554, 8000, 8080, 8443, 8554, 8899,
    9000, 37777, 37778, 34567, 49152
]


def print_banner():
    print("=" * 70)
    print("            MB INSPECTOR - AUDITORIA DE REDE E CFTV           ")
    print("=" * 70)


def run(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:
        return 1, "", str(exc)


def find_nmap():
    return shutil.which("nmap") or shutil.which("nmap.exe")


def load_inventory(filepath: Path):
    if filepath.exists():
        try:
            return json.loads(filepath.read_text(encoding="utf-8"))
        except Exception:
            pass

    return {
        "devices": [],
        "scans": []
    }


def save_inventory(data, filepath: Path):
    filepath.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def discover_hosts(network):
    nmap = find_nmap()

    if not nmap:
        print("\n[ERRO] Nmap não foi encontrado no seu sistema.")
        print("Para funcionar corretamente, instale o Nmap e certifique-se de adicioná-lo ao PATH do Windows.\n")
        sys.exit(1)

    print(f"\n[1/3] Descobrindo dispositivos ativos na rede {network}...")

    rc, output, error = run([
        nmap,
        "-sn",
        "-PR",
        network
    ])

    if rc != 0:
        print("\n[ERRO] Houve uma falha ao executar a varredura com Nmap:")
        print(error)
        sys.exit(1)

    ips = []

    for line in output.splitlines():
        if "Nmap scan report for" not in line:
            continue

        host = line.split("for", 1)[1].strip()

        if "(" in host:
            ip = host.rsplit("(", 1)[-1].rstrip(")")
        else:
            ip = host

        try:
            ips.append(str(ipaddress.ip_address(ip)))
        except ValueError:
            pass

    return sorted(
        set(ips),
        key=lambda value: ipaddress.ip_address(value)
    )


def scan_services(ip, aggressive=False):
    nmap = find_nmap()

    ports = COMMON_PORTS if aggressive else CAMERA_PORTS
    port_string = ",".join(str(p) for p in ports)

    rc, output, error = run([
        nmap,
        "-Pn",
        "-sV",
        "--open",
        "-p",
        port_string,
        ip
    ])

    services = []

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 3:
            continue

        port_field = parts[0]

        if "/" not in port_field:
            continue

        port_text, protocol = port_field.split("/", 1)

        if not port_text.isdigit():
            continue

        try:
            port = int(port_text)
        except ValueError:
            continue

        state = parts[1]
        service = parts[2]

        version = " ".join(parts[3:])

        services.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version
        })

    return services


def perform_scan(network, aggressive=False):
    ips = discover_hosts(network)

    print(f"\n[2/3] Mapeamento concluído! Dispositivos encontrados: {len(ips)}")
    print("[3/3] Identificando portas e serviços de cada equipamento...")

    devices = []

    for index, ip in enumerate(ips, start=1):
        print(f"  -> [{index:02d}/{len(ips):02d}] Analisando {ip}...")

        services = scan_services(ip, aggressive)

        try:
            hostname = socket.getfqdn(ip)
        except Exception:
            hostname = ""

        devices.append({
            "ip": ip,
            "hostname": hostname,
            "online": True,
            "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "services": services,
            "notes": ""
        })

    return devices


def compare(old_devices, new_devices):
    old = {device["ip"]: device for device in old_devices}
    new = {device["ip"]: device for device in new_devices}

    print("\n----------------------------------------------------------------------")
    print("                RESUMO DE ALTERAÇÕES EM RELAÇÃO À ÚLTIMA VARREDURA    ")
    print("----------------------------------------------------------------------")

    has_changes = False

    for ip in sorted(set(new) - set(old), key=ipaddress.ip_address):
        has_changes = True
        print(f"  [+] NOVO DISPOSITIVO NOVO : {ip} ({classify(new[ip])})")

    for ip in sorted(set(old) - set(new), key=ipaddress.ip_address):
        has_changes = True
        print(f"  [-] DISPOSITIVO AUSENTE   : {ip} (não respondeu à varredura)")

    for ip in sorted(set(old) & set(new), key=ipaddress.ip_address):
        old_ports = {service["port"] for service in old[ip].get("services", [])}
        new_ports = {service["port"] for service in new[ip].get("services", [])}

        if old_ports != new_ports:
            has_changes = True
            print(f"  [*] PORTAS ALTERADAS     : {ip} | Antes: {sorted(old_ports)} -> Agora: {sorted(new_ports)}")

    if not has_changes:
        print("  (Nenhuma alteração detectada desde a última leitura)")


def classify(device):
    ports = {service["port"] for service in device.get("services", [])}

    if 554 in ports or 8554 in ports:
        return "Câmera CFTV (Provável)"

    if 37777 in ports or 34567 in ports:
        return "DVR/NVR (Provável)"

    if 23 in ports:
        return "Aparelho com Telnet (Atenção)"

    if 445 in ports:
        return "Computador / Servidor"

    return "Dispositivo Genérico"


def save_csv(devices, csv_path: Path):
    with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["IP", "Tipo estimado", "Portas abertas", "Serviços", "Data"])

        for device in devices:
            ports = ",".join(str(service["port"]) for service in device.get("services", []))
            services = "; ".join(
                f'{service["port"]}/{service["service"]} {service["version"]}'.strip()
                for service in device.get("services", [])
            )

            writer.writerow([
                device["ip"],
                classify(device),
                ports,
                services,
                device["scanned_at"]
            ])


def save_txt(devices, txt_path: Path):
    lines = ["=======================================================================",
             "                MB INSPECTOR - RELATÓRIO FORMATADO                     ",
             "=======================================================================\n",
             "Dispositivos com portas acessíveis encontradas:\n"]

    for device in devices:
        services = device.get("services", [])
        if not services:
            continue

        hostname = f" ({device['hostname']})" if device.get("hostname") and device["hostname"] != device["ip"] else ""
        lines.append(f"* {device['ip']}{hostname}")

        for s in services:
            port = s.get("port")
            service_name = s.get("service", "").upper()
            version = s.get("version", "").strip()

            if service_name and version:
                details = f"{service_name} - {version}"
            elif service_name:
                details = service_name
            elif version:
                details = version
            else:
                details = ""

            info = f" ({details})" if details else ""
            lines.append(f"    - Porta {port}{info}")

    txt_path.write_text("\n".join(lines), encoding="utf-8")


def show_devices(devices):
    print("\n----------------------------------------------------------------------")
    print(f"{'ENDEREÇO IP':<16} {'TIPO ESTIMADO':<30} {'PORTAS ABERTAS'}")
    print("----------------------------------------------------------------------")

    if not devices:
        print(" Nenhum dispositivo foi encontrado ou listado.")
        return

    for device in devices:
        ports = ",".join(str(service["port"]) for service in device.get("services", [])) or "-"
        print(f'{device["ip"]:<16} {classify(device):<30} {ports}')


def interactive_menu():
    print_banner()
    print("\nBem-vindo ao MB Inspector!")
    print("Escolha uma opção para continuar:\n")
    print(" [1] Iniciar nova varredura de rede (Scan)")
    print(" [2] Visualizar relatório existente (Show)")
    print(" [0] Sair\n")

    opcao = input("Opção desejada (1, 2 ou 0): ").strip()

    if opcao == "1":
        network = input("\nInforme a faixa de rede (ex: 192.168.1.0/24): ").strip()
        if not network:
            print("Faixa de rede inválida. Operação cancelada.")
            return

        nome_arquivo = input("Nome para salvar o relatório (padrão: inventory): ").strip() or "inventory"
        agressivo_resp = input("Deseja fazer varredura completa de portas (S/N)? ").strip().lower()
        agressivo = agressivo_resp == 's'

        run_scan(network, nome_arquivo, agressivo)

    elif opcao == "2":
        nome_arquivo = input("\nNome do arquivo para abrir (padrão: inventory): ").strip() or "inventory"
        run_show(nome_arquivo)

    else:
        print("\nSaindo... Atéquais!")


def run_scan(network, output_file, aggressive):
    json_filename = output_file if output_file.endswith(".json") else f"{output_file}.json"

    inventory_path = DATA_DIR / json_filename
    csv_path = DATA_DIR / inventory_path.with_suffix(".csv").name
    txt_path = DATA_DIR / inventory_path.with_suffix(".txt").name

    data = load_inventory(inventory_path)
    new_devices = perform_scan(network, aggressive)
    old_devices = data.get("devices", [])

    if old_devices:
        compare(old_devices, new_devices)

    data["devices"] = new_devices
    data["scans"].append({
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "network": network,
        "count": len(new_devices)
    })

    save_inventory(data, inventory_path)
    save_csv(new_devices, csv_path)
    save_txt(new_devices, txt_path)

    show_devices(new_devices)

    print("\n================================================================------")
    print("                         RELATÓRIOS GERADOS COM SUCESSO               ")
    print("================================================================------")
    print(f" [JSON] : {inventory_path}")
    print(f" [CSV]  : {csv_path}")
    print(f" [TXT]  : {txt_path}")
    print("================================================================------\n")


def run_show(output_file):
    json_filename = output_file if output_file.endswith(".json") else f"{output_file}.json"
    inventory_path = DATA_DIR / json_filename

    if not inventory_path.exists():
        print(f"\n[ERRO] Não foi encontrado nenhum arquivo de inventário com o nome '{json_filename}'.")
        return

    data = load_inventory(inventory_path)
    show_devices(data.get("devices", []))


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description="MB Inspector - Auditoria e Inventário de Rede")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Realiza a varredura em uma rede")
    scan_parser.add_argument("network", help="Faixa de rede IP (ex: 192.168.10.0/24)")
    scan_parser.add_argument("--aggressive", action="store_true", help="Verifica lista ampliada de portas")
    scan_parser.add_argument("-o", "--out", "--nome", "--name", "-n", dest="output_file", default="inventory.json", help="Nome do arquivo para salvar")

    show_parser = subparsers.add_parser("show", help="Mostra um relatório salvo")
    show_parser.add_argument("-o", "--out", "--nome", "--name", "-n", dest="output_file", default="inventory.json", help="Nome do arquivo salvo para carregar")

    args = parser.parse_args()

    print_banner()

    if args.command == "scan":
        run_scan(args.network, args.output_file, args.aggressive)
    elif args.command == "show":
        run_show(args.output_file)


if __name__ == "__main__":
    main()