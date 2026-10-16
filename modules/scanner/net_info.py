"""
Resumen Ejecutivo de Red y Conectividad del Host.
Muestra información detallada sobre la configuración IP local, gateway, DNS y WAN pública.
"""
import socket
import platform
import requests
import dns.resolver
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.ui import console, print_section_header, print_info, print_error
from core.utils import get_outbound_ip, get_default_gateway
from core.oui import get_vendor

def get_gateway_mac(gateway_ip: str) -> str:
    """Intenta resolver la dirección MAC de la puerta de enlace mediante SendARP."""
    import ctypes
    import struct
    try:
        dest_ip = struct.unpack('<I', socket.inet_aton(gateway_ip))[0]
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0:
            return ':'.join(f'{b:02X}' for b in mac_buf)
    except Exception:
        pass
    return "No disponible"

def show_network_summary():
    """
    Recopila y presenta una radiografía completa de la conectividad
    de red actual tanto interna (LAN) como externa (WAN/Internet).
    """
    print_section_header("Resumen Ejecutivo de Conectividad de Red", "Parámetros del Host, Interfaces Activas y Conexión WAN")
    
    with console.status("[bold cyan]Recopilando telemetría de red local y pública...", spinner="dots"):
        hostname = socket.gethostname()
        local_ip = get_outbound_ip()
        gateway_ip = get_default_gateway()
        gateway_mac = get_gateway_mac(gateway_ip) if gateway_ip != "No detectada" else "N/A"
        gateway_vendor = get_vendor(gateway_mac) if gateway_mac != "No disponible" else "N/A"

        # DNS del sistema
        try:
            resolver = dns.resolver.Resolver()
            system_dns = ", ".join(resolver.nameservers[:3])
        except Exception:
            system_dns = "Desconocido"

        # WAN Pública
        public_ip = "No disponible"
        isp = "Desconocido"
        location = "Desconocido"
        try:
            resp = requests.get("https://ipinfo.io/json", timeout=2.5)
            if resp.status_code == 200:
                data = resp.json()
                public_ip = data.get("ip", "N/A")
                isp = data.get("org", "N/A")
                city = data.get("city", "")
                region = data.get("region", "")
                country = data.get("country", "")
                location = f"{city}, {region} ({country})".strip(", ")
        except Exception:
            try:
                resp_ip = requests.get("https://api.ipify.org?format=json", timeout=2.0)
                if resp_ip.status_code == 200:
                    public_ip = resp_ip.json().get("ip", "N/A")
            except Exception:
                pass

    table = Table(title="Telemetría de Red del Sistema", box=box.ROUNDED)
    table.add_column("Parámetro", style="bold cyan", width=28)
    table.add_column("Valor Actual", style="bold white")
    table.add_column("Detalle / Observaciones", style="dim white")

    table.add_row("Nombre del Equipo (Host)", hostname, platform.platform())
    table.add_row("IP Local (Ruta Saliente)", local_ip, "Dirección IPv4 privada asignada")
    table.add_row("Puerta de Enlace (Gateway)", gateway_ip, f"MAC: {gateway_mac} ({gateway_vendor})")
    table.add_row("Servidores DNS Primarios", system_dns, "Resolución de nombres local")
    table.add_row("IP Pública Externa (WAN)", public_ip, f"ISP: {isp}")
    table.add_row("Ubicación WAN Aproximada", location, "Geolocalización por ASN del proveedor")

    console.print(table)
