"""
Herramienta de Diagnóstico DNS Integral y Benchmark de Servidores DNS.
Consulta de registros (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR) y comparación de latencia entre resolvers públicos.
"""
import time
import socket
import dns.resolver
import dns.reversename
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, print_warning, get_input
from core.utils import is_valid_ipv4

PUBLIC_DNS_SERVERS = [
    ("Cloudflare Primario", "1.1.1.1"),
    ("Cloudflare Secundario", "1.0.0.1"),
    ("Google Primario", "8.8.8.8"),
    ("Google Secundario", "8.8.4.4"),
    ("Quad9 Seguro", "9.9.9.9"),
    ("OpenDNS Home", "208.67.222.222"),
]

def query_dns_records(domain: str):
    """
    Consulta todos los registros DNS principales de un dominio determinado
    y presenta la información de forma estructurada.
    """
    domain = domain.strip().lower()
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split('/')[0]

    console.print(f"[bold cyan]▶ Analizando registros DNS para: [bold white]{domain}[/bold white]...[/bold cyan]\n")

    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    table = Table(title=f"Zona DNS: {domain}", box=box.ROUNDED)
    table.add_column("Tipo", style="bold cyan", justify="center")
    table.add_column("TTL", style="yellow", justify="right")
    table.add_column("Valor / Registro", style="white")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    found_any = False

    for r_type in record_types:
        try:
            answers = resolver.resolve(domain, r_type)
            for rdata in answers:
                found_any = True
                val = rdata.to_text()
                # Limpiar comillas extras en TXT si las tiene
                if r_type == "TXT":
                    val = val.strip('"')
                table.add_row(r_type, str(answers.rrset.ttl), val)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception:
            continue

    if found_any:
        console.print(table)
    else:
        print_warning(f"No se encontraron registros para el dominio '{domain}' o el dominio no existe.")

def reverse_dns_lookup(ip: str):
    """Realiza una consulta de DNS Inverso (PTR) para una dirección IP."""
    if not is_valid_ipv4(ip):
        print_error(f"La dirección '{ip}' no es una IPv4 válida.")
        return

    console.print(f"[bold cyan]▶ Realizando búsqueda inversa (PTR) para: [bold white]{ip}[/bold white]...[/bold cyan]\n")
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        answers = resolver.resolve(rev_name, "PTR")
        
        table = Table(title="Resultado DNS Inverso (PTR)", box=box.ROUNDED)
        table.add_column("Dirección IP", style="bold cyan")
        table.add_column("Hostname Resuelto (FQDN)", style="bold green")

        for rdata in answers:
            table.add_row(ip, rdata.to_text())
        console.print(table)
    except Exception as e:
        print_warning(f"No se encontró registro PTR para {ip} ({e}).")

def benchmark_dns_servers(domain: str = "google.com"):
    """
    Compara el tiempo de respuesta y la latencia de resolución de múltiples
    servidores DNS públicos reconocidos versus el DNS local del sistema.
    """
    console.print(f"[bold cyan]▶ Comparando tiempos de resolución para [bold white]{domain}[/bold white]...[/bold cyan]\n")

    results = []
    
    # 1. Probar DNS Local
    try:
        local_resolver = dns.resolver.Resolver()
        t_start = time.perf_counter()
        ans = local_resolver.resolve(domain, "A")
        t_ms = (time.perf_counter() - t_start) * 1000.0
        ip_res = ans[0].to_text()
        results.append(("DNS Local del Sistema", ", ".join(local_resolver.nameservers[:2]), f"{t_ms:.2f}", ip_res, t_ms))
    except Exception as e:
        results.append(("DNS Local del Sistema", "Local", "Fallo", str(e), 9999))

    # 2. Probar Servidores Públicos
    for name, dns_ip in PUBLIC_DNS_SERVERS:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [dns_ip]
        res.timeout = 2.0
        res.lifetime = 2.0
        try:
            t_start = time.perf_counter()
            ans = res.resolve(domain, "A")
            t_ms = (time.perf_counter() - t_start) * 1000.0
            ip_res = ans[0].to_text()
            results.append((name, dns_ip, f"{t_ms:.2f}", ip_res, t_ms))
        except Exception:
            results.append((name, dns_ip, "Timeout", "Sin respuesta", 9999))

    # Ordenar por tiempo de respuesta
    results.sort(key=lambda x: x[4])

    table = Table(title=f"Benchmark de Servidores DNS para '{domain}'", box=box.ROUNDED)
    table.add_column("Ranking", style="bold cyan", justify="center")
    table.add_column("Proveedor", style="white")
    table.add_column("Servidor IP", style="dim white")
    table.add_column("Latencia (ms)", style="bold yellow", justify="right")
    table.add_column("IP Resuelta", style="green")

    for i, (name, srv_ip, lat_str, ip_res, _) in enumerate(results, 1):
        rank_str = f"#{i}"
        if i == 1:
            rank_str = "[bold green]🥇 #1 Más rápido[/bold green]"
        elif i == 2:
            rank_str = "[cyan]🥈 #2[/cyan]"
        elif i == 3:
            rank_str = "[yellow]🥉 #3[/yellow]"
        table.add_row(rank_str, name, srv_ip, f"{lat_str} ms" if lat_str != "Timeout" and lat_str != "Fallo" else f"[red]{lat_str}[/red]", ip_res)

    console.print(table)

def dns_menu():
    """Submenú interactivo para diagnósticos DNS."""
    print_section_header("Auditoría y Diagnóstico DNS", "Inspección de zonas, registros autoritativos y benchmark de resolvers")
    
    console.print("  [bold 1]1.[/bold 1] Consultar Registros DNS de Dominio (A, AAAA, MX, TXT, NS, SOA, CNAME)")
    console.print("  [bold 2]2.[/bold 2] Búsqueda Inversa DNS / PTR (IP -> Hostname)")
    console.print("  [bold 3]3.[/bold 3] Benchmark de Servidores DNS Públicos (Cloudflare, Google, Quad9, Local)")
    
    choice = get_input("Seleccione una opción", default="1")

    if choice == "1":
        domain = get_input("Ingrese el nombre de dominio a auditar", default="microsoft.com")
        if domain:
            query_dns_records(domain)
    elif choice == "2":
        ip = get_input("Ingrese la dirección IPv4 a consultar", default="8.8.8.8")
        if ip:
            reverse_dns_lookup(ip)
    elif choice == "3":
        test_domain = get_input("Dominio para probar velocidad de resolución", default="cloudflare.com")
        if test_domain:
            benchmark_dns_servers(test_domain)
