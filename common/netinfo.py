"""Trouver l'adresse IP à laquelle les autres machines du réseau local peuvent joindre ce poste.

Cas particulier de WSL2 en mode NAT : Linux voit une adresse interne (172.x) injoignable depuis le
réseau. L'adresse utile est celle de Windows, et Windows doit rediriger le port vers WSL (portproxy).
"""
import functools
import ipaddress
import re
import socket
import subprocess

POWERSHELL = "powershell.exe"
NETSH = "netsh.exe"
FIREWALL_RULE = "RelaisMessagerieChiffree"


def local_ip():
    """Adresse de l'interface qui sert à sortir vers le réseau (aucun paquet n'est envoyé)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


@functools.cache
def in_wsl():
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _run(cmd, timeout=20):
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return out.stdout.decode("utf-8", errors="replace").replace("\r", "")
    except (OSError, subprocess.SubprocessError):
        return ""


@functools.cache
def windows_lan_ip():
    """Adresse IPv4 de Windows sur l'interface qui a une passerelle (Wi-Fi ou Ethernet)."""
    out = _run([POWERSHELL, "-NoProfile", "-Command",
                "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and "
                "$_.NetAdapter.Status -eq 'Up' }).IPv4Address.IPAddress"])
    for line in out.split():
        try:
            ip = ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback:
            return str(ip)
    return None


def lan_info(port):
    """Ce qu'il faut savoir pour que les autres se connectent à ce poste."""
    ip = local_ip()
    info = {"ip": ip, "url": f"http://{ip}:{port}", "wsl_nat": False, "wsl_ip": None, "forwarded": None}
    if in_wsl():
        win_ip = windows_lan_ip()
        if win_ip and win_ip != ip:  # mode NAT : l'adresse Linux n'est pas visible du réseau
            info.update(ip=win_ip, url=f"http://{win_ip}:{port}", wsl_nat=True, wsl_ip=ip,
                        forwarded=portproxy_ok(port, ip))
    return info


def portproxy_ok(port, wsl_ip):
    """La redirection Windows → WSL existe-t-elle déjà pour ce port et cette adresse WSL ?"""
    out = _run([NETSH, "interface", "portproxy", "show", "v4tov4"], timeout=10)
    pattern = rf"^\s*\S+\s+{port}\s+{re.escape(wsl_ip)}\s+{port}\s*$"
    return bool(re.search(pattern, out, re.MULTILINE))


def forward_commands(port, wsl_ip):
    """Commandes Windows (administrateur) pour ouvrir le port aux autres machines."""
    return [
        f"netsh interface portproxy delete v4tov4 listenport={port} listenaddress=0.0.0.0",
        f"netsh interface portproxy add v4tov4 listenport={port} listenaddress=0.0.0.0 "
        f"connectport={port} connectaddress={wsl_ip}",
        f"netsh advfirewall firewall delete rule name={FIREWALL_RULE}{port}",
        f"netsh advfirewall firewall add rule name={FIREWALL_RULE}{port} dir=in action=allow "
        f"protocol=TCP localport={port}",
    ]


def setup_wsl_forward(port, wsl_ip):
    """Lance les commandes dans un PowerShell administrateur (Windows affiche une confirmation)."""
    script = "; ".join(forward_commands(port, wsl_ip))
    _run([POWERSHELL, "-NoProfile", "-Command",
          f"Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden "
          f"-ArgumentList '-NoProfile -Command \"{script}\"'"], timeout=120)
    return portproxy_ok(port, wsl_ip)
