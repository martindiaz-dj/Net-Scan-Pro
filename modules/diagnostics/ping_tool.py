"""
Herramienta de Ping Profesional (ICMP y TCP).
Permite diagnósticos de latencia, pérdida de paquetes y jitter tanto a nivel de red (ICMP)
como a nivel de aplicación (TCP Handshake) para eludir bloqueos de firewall.
"""
import re
import socket
import subprocess
import time
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, print_warning, get_input
from core.utils import get_default_gateway

def run_icmp_ping(target: str, count: int = 4, timeout_ms: int = 1000):
    """
    Ejecuta un Ping ICMP utilizando el subsistema de red nativo,
    mostrando los resultados en una tabla estructurada y calculando estadísticas.
    """
    console.print(f"[bold cyan]▶ Iniciando Ping ICMP a [bold white]{target}[/bold white] ({count} paquetes, timeout {timeout_ms}ms)...[/bold cyan]\n")

    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    
    table = Table(title=f"Resultados ICMP: {target}", box=box.ROUNDED)
    table.add_column("Secuencia", style="cyan", justify="center")
    table.add_column("Respuesta Desde", style="white")
    table.add_column("Bytes", style="green", justify="right")
    table.add_column("Tiempo (ms)", style="bright_yellow", justify="right")
    table.add_column("TTL", style="magenta", justify="center")
    table.add_column("Estado", style="bold")

    rtts = []
    sent = 0
    received = 0

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="latin1")
        seq = 1
        for line in proc.stdout:
            line_str = line.strip()
            # Detección de respuesta exitosa (Español e Inglés)
            # Ej: Respuesta desde 8.8.8.8: bytes=32 tiempo=19ms TTL=250
            # Ej: Reply from 8.8.8.8: bytes=32 time=19ms TTL=250
            match_reply = re.search(r'(?:desde|from)\s+([^\s:]+).*?bytes=(\d+).*?(?:tiempo|time)[=<](\d+)ms.*?TTL=(\d+)', line_str, re.IGNORECASE)
            # Detección de tiempo menor a 1ms
            if not match_reply:
                match_reply = re.search(r'(?:desde|from)\s+([^\s:]+).*?bytes=(\d+).*?(?:tiempo|time)<1ms.*?TTL=(\d+)', line_str, re.IGNORECASE)
                if match_reply:
                    from_ip = match_reply.group(1)
                    bytes_val = match_reply.group(2)
                    time_val = 0.5
                    ttl_val = match_reply.group(3)
                    rtts.append(time_val)
                    received += 1
                    sent += 1
                    table.add_row(f"#{seq}", from_ip, bytes_val, "<1 ms", str(ttl_val), "[green]✔ OK[/green]")
                    seq += 1
                    continue

            if match_reply:
                from_ip = match_reply.group(1)
                bytes_val = match_reply.group(2)
                time_val = float(match_reply.group(3))
                ttl_val = match_reply.group(4)
                rtts.append(time_val)
                received += 1
                sent += 1
                table.add_row(f"#{seq}", from_ip, bytes_val, f"{time_val:.0f} ms", str(ttl_val), "[green]✔ OK[/green]")
                seq += 1
            elif "tiempo de espera agotado" in line_str.lower() or "request timed out" in line_str.lower():
                sent += 1
                table.add_row(f"#{seq}", target, "-", "-", "-", "[red]✖ Timeout[/red]")
                seq += 1
            elif "host de destino inaccesible" in line_str.lower() or "destination host unreachable" in line_str.lower():
                sent += 1
                table.add_row(f"#{seq}", target, "-", "-", "-", "[red]✖ Inaccesible[/red]")
                seq += 1

        proc.wait()
    except Exception as e:
        print_error(f"Error al ejecutar ping ICMP: {e}")
        return

    console.print(table)

    lost = sent - received
    loss_pct = (lost / sent * 100) if sent > 0 else 0

    stats_table = Table(title="Estadísticas de Conectividad", box=box.SIMPLE)
    stats_table.add_column("Métrica", style="cyan")
    stats_table.add_column("Valor", style="bold white")

    stats_table.add_row("Paquetes Enviados", str(sent))
    stats_table.add_row("Paquetes Recibidos", str(received))
    stats_table.add_row("Paquetes Perdidos", f"{lost} ({loss_pct:.1f}%)")

    if rtts:
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        avg_rtt = sum(rtts) / len(rtts)
        stats_table.add_row("Latencia Mínima", f"{min_rtt:.1f} ms")
        stats_table.add_row("Latencia Máxima", f"{max_rtt:.1f} ms")
        stats_table.add_row("Latencia Media", f"{avg_rtt:.1f} ms")
    
    console.print()
    console.print(stats_table)

def run_tcp_ping(target: str, port: int = 80, count: int = 4, timeout: float = 2.0):
    """
    Ejecuta un Ping a nivel TCP mediante Three-Way Handshake SYN/ACK.
    Excelente cuando los cortafuegos bloquean ICMP pero el servicio está escuchando.
    Calcula además el Jitter (variabilidad de retardo).
    """
    console.print(f"[bold cyan]▶ Iniciando Ping TCP a [bold white]{target}:{port}[/bold white] ({count} intentos, timeout {timeout}s)...[/bold cyan]\n")

    table = Table(title=f"Resultados TCP Ping: {target}:{port}", box=box.ROUNDED)
    table.add_column("Secuencia", style="cyan", justify="center")
    table.add_column("Destino", style="white")
    table.add_column("Puerto", style="bright_blue", justify="center")
    table.add_column("Tiempo RTT (ms)", style="bright_yellow", justify="right")
    table.add_column("Jitter (ms)", style="magenta", justify="right")
    table.add_column("Estado", style="bold")

    rtts = []
    jitters = []
    sent = 0
    received = 0

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print_error(f"No se pudo resolver el nombre de host '{target}': {e}")
        return

    for i in range(1, count + 1):
        sent += 1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start_time = time.perf_counter()
        status_text = ""
        rtt_ms = None

        try:
            res = s.connect_ex((resolved_ip, port))
            end_time = time.perf_counter()
            s.close()
            
            if res == 0:
                rtt_ms = (end_time - start_time) * 1000.0
                rtts.append(rtt_ms)
                received += 1
                jitter_val = 0.0
                if len(rtts) > 1:
                    jitter_val = abs(rtts[-1] - rtts[-2])
                    jitters.append(jitter_val)
                jitter_str = f"{jitter_val:.2f} ms" if len(rtts) > 1 else "-"
                table.add_row(f"#{i}", f"{target} ({resolved_ip})", str(port), f"{rtt_ms:.2f} ms", jitter_str, "[green]✔ Conectado (SYN/ACK)[/green]")
            else:
                table.add_row(f"#{i}", f"{target} ({resolved_ip})", str(port), "-", "-", f"[yellow]⚠ Rechazado (Código {res})[/yellow]")
        except socket.timeout:
            table.add_row(f"#{i}", f"{target} ({resolved_ip})", str(port), "-", "-", "[red]✖ Timeout (Sin respuesta)[/red]")
        except Exception as e:
            table.add_row(f"#{i}", f"{target} ({resolved_ip})", str(port), "-", "-", f"[red]✖ Error: {e}[/red]")
        
        if i < count:
            time.sleep(0.5)

    console.print(table)

    lost = sent - received
    loss_pct = (lost / sent * 100) if sent > 0 else 0

    stats_table = Table(title="Métricas de Conexión TCP", box=box.SIMPLE)
    stats_table.add_column("Métrica", style="cyan")
    stats_table.add_column("Valor", style="bold white")

    stats_table.add_row("Intentos Enviados", str(sent))
    stats_table.add_row("Respuestas Exitosas", str(received))
    stats_table.add_row("Pérdida / Falla", f"{lost} ({loss_pct:.1f}%)")

    if rtts:
        stats_table.add_row("Latencia Mínima", f"{min(rtts):.2f} ms")
        stats_table.add_row("Latencia Máxima", f"{max(rtts):.2f} ms")
        stats_table.add_row("Latencia Media", f"{(sum(rtts)/len(rtts)):.2f} ms")
    if jitters:
        avg_jitter = sum(jitters) / len(jitters)
        stats_table.add_row("Jitter Medio (Varianza)", f"{avg_jitter:.2f} ms")

    console.print()
    console.print(stats_table)

def ping_menu():
    """Submenú interactivo para herramientas de Ping."""
    print_section_header("Herramientas de Ping & Latencia", "Diagnóstico de conectividad ICMP estándar y TCP Handshake")
    
    default_gw = get_default_gateway()
    console.print(f"[dim]Sugerencia: Gateway local: {default_gw} | DNS Cloudflare: 1.1.1.1 | DNS Google: 8.8.8.8[/dim]\n")
    
    target = get_input("Ingrese la IP o Dominio de destino", default="1.1.1.1")
    if not target:
        return

    console.print("\n[bold cyan]Seleccione el método de prueba:[/bold cyan]")
    console.print("  [bold 1]1.[/bold 1] Ping ICMP Estándar (Nivel 3 - IP/ICMP)")
    console.print("  [bold 2]2.[/bold 2] Ping TCP Handshake (Nivel 4 - Puerto de servicio / Anti-Firewall)")
    console.print("  [bold 3]3.[/bold 3] Ambos en paralelo (Diagnóstico completo comparativo)")
    
    choice = get_input("Opción", default="1")

    if choice == "1":
        count_str = get_input("Cantidad de paquetes a enviar", default="4")
        count = int(count_str) if count_str.isdigit() else 4
        run_icmp_ping(target, count=count)
    elif choice == "2":
        port_str = get_input("Puerto TCP a probar (ej. 80=HTTP, 443=HTTPS, 22=SSH, 3389=RDP)", default="443")
        port = int(port_str) if port_str.isdigit() else 443
        count_str = get_input("Cantidad de intentos", default="4")
        count = int(count_str) if count_str.isdigit() else 4
        run_tcp_ping(target, port=port, count=count)
    elif choice == "3":
        port_str = get_input("Puerto TCP para la prueba", default="443")
        port = int(port_str) if port_str.isdigit() else 443
        console.print()
        run_icmp_ping(target, count=4)
        console.print()
        run_tcp_ping(target, port=port, count=4)
