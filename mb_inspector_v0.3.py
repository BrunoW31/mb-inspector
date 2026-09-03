#!/usr/bin/env python3
# MB Inspector v0.3
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

# Portas comuns em CFTV. A lista pode ser ampliada depois.
CAMERA_PORTS = [
    80, 443, 554, 8000, 8080, 8443, 8554,
    8899, 37777, 37778, 34567, 5000
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 443, 445,
    554, 8000, 8080, 8443, 8554, 8899,
    9000, 37777, 37778, 34567, 49152
]


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
        print("ERRO: Nmap não encontrado.")
        print("Instale o Nmap e coloque o executável no PATH do Windows.")
        sys.exit(1)

    print(f"[+] Descobrindo dispositivos em {network}...")

    rc, output, error = run([
        nmap,
        "-sn",
        "-PR",
        network
    ])

    if rc != 0:
        print("Erro no Nmap:")
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

    print(f"[+] Hosts encontrados: {len(ips)}")

    devices = []

    for index, ip in enumerate(ips, start=1):
        print(
            f"[{index}/{len(ips)}] "
            f"{ip} -> verificando portas e serviços..."
        )

        services = scan_services(ip, aggressive)

        try:
            hostname = socket.getfqdn(ip)
        except Exception:
            hostname = ""

        devices.append({
            "ip": ip,
            "hostname": hostname,
            "online": True,
            "scanned_at": datetime.datetime.now().isoformat(
                timespec="seconds"
            ),
            "services": services,
            "notes": ""
        })

    return devices


def compare(old_devices, new_devices):
    old = {device["ip"]: device for device in old_devices}
    new = {device["ip"]: device for device in new_devices}

    print("\n=== ALTERAÇÕES DETECTADAS ===")

    for ip in sorted(
        set(new) - set(old),
        key=ipaddress.ip_address
    ):
        print(
            f"+ NOVO DISPOSITIVO: {ip} "
            f"({classify(new[ip])})"
        )

    for ip in sorted(
        set(old) - set(new),
        key=ipaddress.ip_address
    ):
        print(
            f"- AUSENTE: {ip} "
            f"(não apareceu nesta varredura)"
        )

    for ip in sorted(
        set(old) & set(new),
        key=ipaddress.ip_address
    ):
        old_ports = {
            service["port"]
            for service in old[ip].get("services", [])
        }

        new_ports = {
            service["port"]
            for service in new[ip].get("services", [])
        }

        if old_ports != new_ports:
            print(
                f"* PORTAS ALTERADAS: {ip} | "
                f"antes={sorted(old_ports)} "
                f"agora={sorted(new_ports)}"
            )


def classify(device):
    ports = {
        service["port"]
        for service in device.get("services", [])
    }

    if 554 in ports or 8554 in ports:
        return "provavel_camera_cftv"

    if 37777 in ports or 34567 in ports:
        return "provavel_dvr_nvr"

    if 23 in ports:
        return "dispositivo_com_telnet"

    if 445 in ports:
        return "computador_ou_servidor"

    return "dispositivo"


def save_csv(devices, csv_path: Path):
    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP",
            "Tipo estimado",
            "Portas abertas",
            "Serviços",
            "Data"
        ])

        for device in devices:
            ports = ",".join(
                str(service["port"])
                for service in device.get("services", [])
            )

            services = "; ".join(
                f'{service["port"]}/{service["service"]} '
                f'{service["version"]}'.strip()
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
    lines = ["Dispositivos da rede com portas acessíveis (abertas):"]

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
            lines.append(f"  * Porta {port}{info}")

    txt_path.write_text("\n".join(lines), encoding="utf-8")


def show_devices(devices):
    print("\nIP              TIPO                         PORTAS")
    print("-" * 75)

    for device in devices:
        ports = ",".join(
            str(service["port"])
            for service in device.get("services", [])
        ) or "-"

        print(
            f'{device["ip"]:<15} '
            f'{classify(device):<28} '
            f'{ports}'
        )


def main():
    parser = argparse.ArgumentParser(
        description="MB Inspector v0.3"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="descobre hosts e serviços"
    )

    scan_parser.add_argument(
        "network",
        help="Exemplo: 192.168.10.0/24"
    )

    scan_parser.add_argument(
        "--aggressive",
        action="store_true",
        help="verifica um conjunto maior de portas"
    )

    scan_parser.add_argument(
        "-o", "--out", "--nome", "--name", "-n",
        dest="output_file",
        default="inventory.json",
        help="Nome do arquivo JSON de destino (ex: condominio-teste)"
    )

    show_parser = subparsers.add_parser(
        "show",
        help="mostra um inventário salvo"
    )
    
    show_parser.add_argument(
        "-o", "--out", "--nome", "--name", "-n",
        dest="output_file",
        default="inventory.json",
        help="Nome do arquivo JSON para carregar (padrão: inventory.json)"
    )

    args = parser.parse_args()

    # Trata a extensão do nome informado pelo usuário
    json_filename = args.output_file if hasattr(args, "output_file") else "inventory.json"
    if not json_filename.endswith(".json"):
        json_filename += ".json"

    inventory_path = DATA_DIR / json_filename
    csv_path = DATA_DIR / inventory_path.with_suffix(".csv").name
    txt_path = DATA_DIR / inventory_path.with_suffix(".txt").name

    if args.command == "scan":
        data = load_inventory(inventory_path)

        new_devices = perform_scan(
            args.network,
            args.aggressive
        )

        old_devices = data.get("devices", [])

        if old_devices:
            compare(
                old_devices,
                new_devices
            )

        data["devices"] = new_devices

        data["scans"].append({
            "time": datetime.datetime.now().isoformat(
                timespec="seconds"
            ),
            "network": args.network,
            "count": len(new_devices)
        })

        save_inventory(data, inventory_path)
        save_csv(new_devices, csv_path)
        save_txt(new_devices, txt_path)

        show_devices(new_devices)

        print()
        print("[OK] Inventário salvo em:")
        print(inventory_path)

        print("[OK] CSV salvo em:")
        print(csv_path)

        print("[OK] TXT formatado salvo em:")
        print(txt_path)

    elif args.command == "show":
        data = load_inventory(inventory_path)
        show_devices(
            data.get("devices", [])
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()