"""
Escáner de Puertos TCP Multihilo con Banner Grabbing y Detección de Servicios.
Auditoría rápida y exhaustiva de puertos abiertos, servicios en escucha y versiones de software.
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, print_warning, get_input
from core.utils import parse_port_range

COMMON_SERVICES = {
    21: ("FTP", "Transferencia de Archivos"),
    22: ("SSH", "Secure Shell / Administración Remota"),
    23: ("Telnet", "[bold red]Texto Plano No Seguro[/bold red]"),
    25: ("SMTP", "Envío de Correo"),
    53: ("DNS", "Servicio de Nombres de Dominio"),
    80: ("HTTP", "Servidor Web Sin Cifrar"),
    88: ("Kerberos", "Autenticación de Directorio"),
    110: ("POP3", "Recepción de Correo"),
    111: ("RPCbind", "Llamada a Procedimiento Remoto"),
    135: ("MS-RPC", "Windows Remote Procedure Call"),
    139: ("NetBIOS-SSN", "Compartición de Archivos Windows"),
    143: ("IMAP", "Protocolo de Correo Electrónico"),
    161: ("SNMP", "Gestión y Monitoreo de Red"),
    389: ("LDAP", "Servicio de Directorio Ligero"),
    443: ("HTTPS", "Servidor Web Cifrado SSL/TLS"),
    445: ("SMB", "Compartición de Archivos / Active Directory"),
    465: ("SMTPS", "SMTP Seguro SSL"),
    587: ("Submission", "Envío de Correo Autenticado"),
    636: ("LDAPS", "LDAP Seguro SSL/TLS"),
    993: ("IMAPS", "IMAP Seguro SSL/TLS"),
    995: ("POP3S", "POP3 Seguro SSL/TLS"),
    1433: ("MSSQL", "Base de Datos Microsoft SQL Server"),
    1521: ("Oracle", "Base de Datos Oracle Database"),
    3306: ("MySQL/MariaDB", "Base de Datos Relacional"),
    3389: ("RDP", "Escritorio Remoto de Windows"),
    5432: ("PostgreSQL", "Base de Datos PostgreSQL"),
    5900: ("VNC", "Control Remoto de Escritorio"),
    6379: ("Redis", "Base de Datos en Memoria NoSQL"),
    8000: ("HTTP-Alt", "Servidor Web de Desarrollo"),
    8080: ("HTTP-Proxy", "Proxy Web / Tomcat / Jenkins"),
    8443: ("HTTPS-Alt", "Consola Web de Administración"),
    9000: ("Portainer/Sonar", "Gestión de Contenedores / DevOps"),
    27017: ("MongoDB", "Base de Datos NoSQL"),
}

TOP_25_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017]
TOP_100_PORTS = sorted(list(set(TOP_25_PORTS + [
    20, 69, 79, 81, 82, 88, 102, 113, 119, 123, 144, 162, 179, 199, 264, 311, 389, 427, 444, 464, 465, 497, 500,
    512, 513, 514, 515, 548, 554, 587, 631, 636, 873, 902, 989, 990, 992, 1025, 1080, 1194, 1241, 1434, 1720,
    1723, 1812, 1813, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3128, 3268, 3269, 3690,
    4333, 4840, 5000, 5060, 5222, 5357, 5601, 5672, 6000, 7001, 8008, 8081, 8088, 8181, 8888, 9200, 9300, 11211
])))

def grab_banner(target_ip: str, port: int, timeout: float = 1.2) -> str:
    """
    Intenta extraer el banner o firma de software del servicio abierto
    (ej. versión de SSH, versión de servidor HTTP Apache/Nginx, FTP, etc.).
    """
    banner = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))

        # Puertos web HTTP / HTTPS
        if port in (80, 8080, 8000, 8081):
            req = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\nUser-Agent: NetScanPro/1.0\r\n\r\n"
            s.send(req.encode())
            data = s.recv(1024).decode('latin1', errors='ignore')
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    banner = line.strip()
                    break
        elif port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=target_ip) as ss:
                    req = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\nUser-Agent: NetScanPro/1.0\r\n\r\n"
                    ss.send(req.encode())
                    data = ss.recv(1024).decode('latin1', errors='ignore')
                    for line in data.splitlines():
                        if line.lower().startswith("server:"):
                            banner = line.strip()
                            break
            except Exception:
                pass
        else:
            # Protocolos con banner de bienvenida automático (SSH, FTP, SMTP)
            try:
                data = s.recv(1024).decode('latin1', errors='ignore').strip()
                if data:
                    banner = data.splitlines()[0][:60]
            except socket.timeout:
                pass
        s.close()
    except Exception:
        pass
    return banner if banner else "-"

def probe_port(target_ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Verifica si un puerto TCP específico está abierto mediante un socket connect_ex."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((target_ip, port))
        s.close()
        if res == 0:
            srv_info = COMMON_SERVICES.get(port, ("Desconocido", "Servicio no estándar"))
            banner = grab_banner(target_ip, port, timeout=1.0)
            return {
                "port": port,
                "service": srv_info[0],
                "description": srv_info[1],
                "banner": banner
            }
    except Exception:
        pass
    return None

def scan_target_ports(target: str, ports: list[int], max_workers: int = 40, timeout: float = 1.0) -> list[dict]:
    """
    Escanea la lista de puertos TCP sobre el objetivo usando un pool de hilos,
    mostrando el avance con barra de progreso.
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print_error(f"No se pudo resolver el host '{target}': {e}")
        return []

    total_ports = len(ports)
    console.print(f"[bold cyan]▶ Iniciando escaneo TCP en [bold white]{target}[/bold white] ({target_ip})[/bold cyan]")
    console.print(f"[dim]Total de puertos a verificar: {total_ports} | Concurrencia: {max_workers} hilos | Timeout: {timeout}s[/dim]\n")

    open_ports = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Comprobando puertos...", total=total_ports)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(probe_port, target_ip, p, timeout): p for p in ports}
            for future in as_completed(future_to_port):
                progress.advance(task)
                res = future.result()
                if res:
                    open_ports.append(res)
                    # Notificación breve en consola conforme se descubren
                    srv = res["service"]
                    p_num = res["port"]
                    console.print(f"  [bold green]✔ Puerto ABIERTO:[/bold green] [bold white]{p_num:<5}[/bold white] [cyan]({srv})[/cyan]")

    open_ports.sort(key=lambda x: x["port"])

    table = Table(title=f"Puertos Abiertos en {target} ({target_ip}) - Total: {len(open_ports)}", box=box.ROUNDED)
    table.add_column("Puerto", style="bold cyan", justify="right")
    table.add_column("Servicio", style="bold green")
    table.add_column("Descripción / Función", style="white")
    table.add_column("Banner / Versión Detectada", style="yellow")

    for item in open_ports:
        table.add_row(str(item["port"]), item["service"], item["description"], item["banner"])

    console.print()
    if open_ports:
        console.print(table)
        print_success(f"Escaneo finalizado. Se encontraron {len(open_ports)} puertos abiertos.")
    else:
        print_warning(f"No se detectaron puertos TCP abiertos en el objetivo {target} con los parámetros indicados.")

    return open_ports

def port_scanner_menu():
    """Submenú interactivo para el Escáner de Puertos TCP."""
    print_section_header("Escáner de Puertos TCP & Banner Grabbing", "Auditoría de servicios abiertos y versiones de software")

    target = get_input("Ingrese la IP o Dominio del objetivo", default="127.0.0.1")
    if not target:
        return

    console.print("\n[bold cyan]Seleccione el perfil de escaneo:[/bold cyan]")
    console.print("  [bold 1]1.[/bold 1] Top 25 Puertos Administrativos Críticos (Ultrarrápido, ~1 seg)")
    console.print("  [bold 2]2.[/bold 2] Top 100 Puertos Más Usados de Internet (~3 seg)")
    console.print("  [bold 3]3.[/bold 3] Puertos Well-Known del Sistema (1 al 1024)")
    console.print("  [bold 4]4.[/bold 4] Rango o Lista Personalizada (ej: 80,443,3000-3050,8080)")
    console.print("  [bold 5]5.[/bold 5] Auditoría Completa de Puertos (1 al 65535 - Extensivo)")

    choice = get_input("Opción de perfil", default="1")

    ports = []
    timeout = 1.0
    workers = 40

    if choice == "1":
        ports = TOP_25_PORTS
        workers = 25
    elif choice == "2":
        ports = TOP_100_PORTS
        workers = 50
    elif choice == "3":
        ports = list(range(1, 1025))
        workers = 75
    elif choice == "4":
        custom = get_input("Ingrese puertos o rangos separados por comas", default="22,80,443,3389,8080")
        ports = parse_port_range(custom)
        if not ports:
            print_error("No se ingresaron puertos válidos.")
            return
        workers = min(60, max(20, len(ports)))
    elif choice == "5":
        print_warning("El escaneo de 65,535 puertos puede demorar varios minutos dependiendo de la red.")
        ports = list(range(1, 65536))
        workers = 120
        timeout = 0.8
    else:
        ports = TOP_25_PORTS

    results = scan_target_ports(target, ports, max_workers=workers, timeout=timeout)
    
    if results:
        from core.ui import Confirm
        if Confirm.ask("\n¿Desea exportar los puertos abiertos a un reporte?", default=False):
            from modules.report.exporter import export_scan_results
            export_scan_results("port_scan", {"target": target, "open_ports": results})
