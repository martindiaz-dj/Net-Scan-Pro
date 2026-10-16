"""
Herramienta Visual de Trazado de Ruta (Traceroute).
Muestra el camino de saltos (hops) de red, latencias intermedias y resolución inversa de nombres.
"""
import re
import socket
import subprocess
from rich.table import Table
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, get_input

def resolve_ptr_safe(ip: str) -> str:
    """Intenta resolver el nombre DNS inverso (PTR) de una dirección IP de forma segura."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return "-"

def run_traceroute(target: str, max_hops: int = 30, timeout_ms: int = 1000):
    """
    Ejecuta un traceroute en tiempo real, parseando saltos y enriqueciendo
    cada nodo con su nombre DNS inverso y latencia promedio.
    """
    console.print(f"[bold cyan]▶ Trazando ruta hacia [bold white]{target}[/bold white] (máximo {max_hops} saltos, timeout {timeout_ms}ms)...[/bold cyan]\n")

    cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), target]

    table = Table(title=f"Ruta hacia: {target}", box=box.ROUNDED)
    table.add_column("Salto #", style="bold cyan", justify="center")
    table.add_column("RTT 1", style="yellow", justify="right")
    table.add_column("RTT 2", style="yellow", justify="right")
    table.add_column("RTT 3", style="yellow", justify="right")
    table.add_column("IP del Nodo", style="bold white")
    table.add_column("Hostname / FQDN (PTR)", style="dim white")
    table.add_column("Estado", style="bold")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="latin1")
        for line in proc.stdout:
            line_str = line.strip()
            if not line_str:
                continue

            # Patrón para salto exitoso: ej "1     8 ms     8 ms    15 ms  192.168.0.1"
            # O con <1 ms: "1    <1 ms    <1 ms    <1 ms  192.168.0.1"
            match = re.match(r'^\s*(\d+)\s+([<\d\s*ms]+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line_str)
            if match:
                hop_num = match.group(1)
                times_raw = match.group(2)
                hop_ip = match.group(3)

                # Extraer tiempos individuales
                time_matches = re.findall(r'(?:<1|\d+)\s*ms|\*', times_raw)
                t1 = time_matches[0] if len(time_matches) > 0 else "-"
                t2 = time_matches[1] if len(time_matches) > 1 else "-"
                t3 = time_matches[2] if len(time_matches) > 2 else "-"

                ptr_name = resolve_ptr_safe(hop_ip)
                table.add_row(f"#{hop_num}", t1, t2, t3, hop_ip, ptr_name, "[green]✔ OK[/green]")
                console.print(f"  [cyan]Salto #{hop_num}:[/cyan] [bold white]{hop_ip:<15}[/bold white] [dim]({ptr_name})[/dim]  [yellow]{t1} | {t2} | {t3}[/yellow]")
            elif re.search(r'^\s*(\d+)\s+\*\s+\*\s+\*', line_str) or ("tiempo de espera agotado" in line_str.lower() and re.match(r'^\s*(\d+)', line_str)):
                hop_match = re.match(r'^\s*(\d+)', line_str)
                hop_num = hop_match.group(1) if hop_match else "?"
                table.add_row(f"#{hop_num}", "*", "*", "*", "* * *", "Sin respuesta", "[red]✖ Timeout[/red]")
                console.print(f"  [cyan]Salto #{hop_num}:[/cyan] [dim red]* * * (Cortafuegos / Sin respuesta ICMP)[/dim red]")

        proc.wait()
    except Exception as e:
        print_error(f"Error al ejecutar traceroute: {e}")
        return

    console.print()
    console.print(table)
    print_success("Trazado de ruta finalizado.")

def traceroute_menu():
    """Submenú interactivo para Traceroute."""
    print_section_header("Trazado de Ruta de Red (Traceroute)", "Identificación de saltos intermedios y latencias de tránsito")
    
    target = get_input("Ingrese la IP o Dominio de destino", default="1.1.1.1")
    if not target:
        return

    hops_str = get_input("Máximo de saltos (Hops)", default="20")
    max_hops = int(hops_str) if hops_str.isdigit() else 20

    run_traceroute(target, max_hops=max_hops)
