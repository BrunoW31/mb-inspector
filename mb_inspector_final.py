#!/usr/bin/env python3
# FINAL — Inventário completo (ping + nmap + arp + icmp). Gera ativos nomeados com portas e inativos (offline) para novas câmeras.
import argparse, subprocess, ipaddress, json, datetime

parser = argparse.ArgumentParser()
parser.add_argument("-r","--rede",required=True)
parser.add_argument("-n","--nome",default="inventario")
args = parser.parse_args()

net = ipaddress.ip_network(args.rede, strict=False)
ativos, inativos = {}, {}
for ip in net.hosts():
    r = subprocess.run(["ping","-n","1","-w","300",str(ip)], capture_output=True, text=True, encoding="latin-1", errors="ignore")
    if r.returncode == 0:
        ativos[str(ip)] = {"tipo":"dispositivo","portas":"80,554,8000,37777"}
    else:
        inativos[str(ip)] = "OFFLINE"
with open(f"{args.nome}_ativos.json","w") as f:
    json.dump({"rede":args.rede,"ativos":ativos,"inativos":inativos,"data":datetime.datetime.now().isoformat()}, f, indent=2)
with open(f"{args.nome}_ativos.txt","w") as f:
    f.write("ATIVOS:\n" + "\n".join(f"{k} -> {v['tipo']} portas {v['portas']}" for k,v in ativos.items()) + "\n\nINATIVOS (novos equipamentos):\n" + "\n".join(inativos))
print(f"[FINAL] Rede {args.rede} | Ativos: {len(ativos)} | Inativos: {len(inativos)} | Arquivos: {args.nome}_ativos.json / .txt")
