"""
Utilidades de validación y formateo para administración de redes.
"""
import ipaddress
import re
import socket
import subprocess

def is_valid_ipv4(ip: str) -> bool:
    """Valida si una cadena es una dirección IPv4 válida."""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    """Valida si una cadena es una red CIDR válida (ej. 192.168.1.0/24)."""
    try:
        ipaddress.IPv4Network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False

def is_valid_mac(mac: str) -> bool:
    """Valida si una cadena es una dirección MAC válida (XX:XX:XX:XX:XX:XX o XX-XX-XX-XX-XX-XX)."""
    clean = re.sub(r'[:-]', '', mac.strip().upper())
    return len(clean) == 12 and all(c in '0123456789ABCDEF' for c in clean)

def clean_mac(mac: str) -> str:
    """Estandariza una dirección MAC al formato XX:XX:XX:XX:XX:XX."""
    raw = re.sub(r'[^0-9A-Fa-f]', '', mac.strip().upper())
    if len(raw) == 12:
        return ':'.join(raw[i:i+2] for i in range(0, 12, 2))
    return mac.strip().upper()

def is_valid_port(port: int) -> bool:
    """Valida si un puerto está en el rango válido de 1 a 65535."""
    return 1 <= port <= 65535

def parse_port_range(port_str: str) -> list[int]:
    """
    Parsea cadenas de puertos como '80', '80,443,8080', '1-1024' o combinaciones '22,80-90,443'.
    """
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-')
                start_p = int(start.strip())
                end_p = int(end.strip())
                if 1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p:
                    # Limitar rango excesivo para evitar desborde de memoria accidental
                    if (end_p - start_p) > 65535:
                        end_p = start_p + 65535
                    for p in range(start_p, end_p + 1):
                        ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(list(ports))

def format_bytes(bytes_count: float) -> str:
    """Convierte bytes a formato legible (B, KB, MB, GB, TB)."""
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    val = float(bytes_count)
    for unit in units:
        if abs(val) < 1024.0 or unit == units[-1]:
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} PB"

def format_speed(bytes_per_sec: float) -> str:
    """Convierte bytes por segundo a tasa de bits/bytes formateada."""
    bits_per_sec = bytes_per_sec * 8
    if bits_per_sec < 1000:
        return f"{bits_per_sec:.0f} bps ({format_bytes(bytes_per_sec)}/s)"
    elif bits_per_sec < 1_000_000:
        return f"{bits_per_sec / 1_000:.2f} Kbps ({format_bytes(bytes_per_sec)}/s)"
    elif bits_per_sec < 1_000_000_000:
        return f"{bits_per_sec / 1_000_000:.2f} Mbps ({format_bytes(bytes_per_sec)}/s)"
    else:
        return f"{bits_per_sec / 1_000_000_000:.2f} Gbps ({format_bytes(bytes_per_sec)}/s)"

def get_outbound_ip() -> str:
    """Determina la IP local activa utilizada para salir a redes externas."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No envía paquetes reales, sólo determina la ruta del socket
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_default_gateway() -> str:
    """Obtiene la IP de la puerta de enlace predeterminada en Windows."""
    try:
        out = subprocess.check_output('route print 0.0.0.0', text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                return parts[2]
    except Exception:
        pass
    return "No detectada"
