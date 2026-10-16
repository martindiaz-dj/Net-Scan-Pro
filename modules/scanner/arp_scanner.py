"""
Escáner de Red Local ARP Multihilo de Alto Rendimiento.
Descubre equipos activos en la LAN, resuelve sus direcciones MAC y fabricantes (OUI),
e identifica nombres de host mediante resolución inversa sin requerir controladores Npcap.
"""
import ctypes
import ipaddress
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, print_warning, get_input
from core.oui import get_vendor
from core.utils import get_outbound_ip, get_default_gateway

def send_arp_probe(ip: str):
    """
    Envía una petición ARP directa mediante la API de bajo nivel de Windows (iphlpapi.SendARP).
    Retorna (ip, mac_str, hostname) si el equipo responde, o None.
    """
    try:
        dest_ip = struct.unpack('<I', socket.inet_aton(ip))[0]
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0:
            mac_str = ':'.join(f'{b:02X}' for b in mac_buf)
            # Intento de resolución inversa de nombre
            hostname = "-"
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                hostname = host
            except Exception:
                pass
            return {
                "ip": ip,
                "mac": mac_str,
                "hostname": hostname,
                "vendor": get_vendor(mac_str)
            }
    except Exception:
        pass
    return None

def scan_arp_network(cidr_str: str, max_workers: int = 50) -> list[dict]:
    """
    Ejecuta un barrido ARP sobre un bloque de red CIDR (ej. 192.168.0.0/24)
    utilizando hilos paralelos y actualizando una barra de progreso visual.
    """
    try:
        net = ipaddress.IPv4Network(cidr_str.strip(), strict=False)
    except ValueError as e:
        print_error(f"Formato de red CIDR no válido: {e}")
        return []

    host_ips = [str(ip) for ip in net.hosts()]
    total_ips = len(host_ips)

    if total_ips == 0:
        print_warning("No hay direcciones de host disponibles en el bloque especificado.")
        return []

    console.print(f"[bold cyan]▶ Iniciando escaneo ARP en [bold white]{cidr_str}[/bold white] ({total_ips} hosts, {max_workers} hilos)...[/bold cyan]\n")

    discovered = []
    local_ip = get_outbound_ip()
    gateway_ip = get_default_gateway()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Sondeando direcciones IP...", total=total_ips)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(send_arp_probe, ip): ip for ip in host_ips}
            for future in as_completed(future_to_ip):
                progress.advance(task)
                res = future.result()
                if res:
                    discovered.append(res)

    # Ordenar por dirección IP numérica
    discovered.sort(key=lambda d: socket.inet_aton(d["ip"]))

    table = Table(title=f"Dispositivos Descubiertos en {cidr_str} (Total: {len(discovered)})", box=box.ROUNDED)
    table.add_column("Dirección IP", style="bold cyan")
    table.add_column("Dirección MAC", style="bold yellow")
    table.add_column("Fabricante (Vendor OUI)", style="green")
    table.add_column("Hostname / NetBIOS", style="white")
    table.add_column("Rol Detectado", style="magenta")

    for host in discovered:
        ip = host["ip"]
        role = "Host / Cliente"
        if ip == gateway_ip:
            role = "[bold yellow]Router / Gateway[/bold yellow]"
        elif ip == local_ip:
            role = "[bold bright_cyan]Este Equipo (Host Actual)[/bold bright_cyan]"

        table.add_row(ip, host["mac"], host["vendor"], host["hostname"], role)

    console.print()
    console.print(table)
    print_success(f"Escaneo ARP completado con éxito. Se detectaron {len(discovered)} dispositivos activos.")

    return discovered

def arp_menu():
    """Submenú interactivo para el Escáner ARP."""
    print_section_header("Escáner ARP LAN Ultrarrápido", "Descubrimiento de hosts, inventario de MAC y fabricantes")

    local_ip = get_outbound_ip()
    # Generar sugerencia de CIDR basada en la IP local (ej. 192.168.0.0/24)
    parts = local_ip.split('.')
    suggested_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "192.168.1.0/24"

    console.print(f"[dim]IP Local detectada: {local_ip} | Subred sugerida: {suggested_cidr}[/dim]\n")
    cidr_input = get_input("Ingrese la red CIDR a escanear", default=suggested_cidr)
    
    if not cidr_input:
        return

    workers_str = get_input("Hilos de concurrencia (10 - 100)", default="50")
    workers = int(workers_str) if workers_str.isdigit() else 50
    workers = max(10, min(150, workers))

    discovered = scan_arp_network(cidr_input, max_workers=workers)
    
    if discovered:
        from core.ui import Confirm
        if Confirm.ask("\n¿Desea exportar los resultados a un reporte?", default=False):
            from modules.report.exporter import export_scan_results
            export_scan_results("arp_scan", {"subnet": cidr_input, "hosts": discovered})
