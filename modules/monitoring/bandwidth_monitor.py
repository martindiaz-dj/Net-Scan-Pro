"""
Monitor en Tiempo Real de Tráfico y Ancho de Banda de Red.
Muestra tasas de descarga (RX) y subida (TX) por segundo con indicadores gráficos en vivo.
"""
import time
import psutil
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.ui import console, print_section_header, print_info
from core.utils import format_speed, format_bytes

def generate_meter(rate_bytes: float, max_ref_bytes: float = 5_000_000) -> str:
    """Genera una barra visual proporcional a la tasa de transferencia."""
    pct = min(1.0, max(0.0, rate_bytes / max_ref_bytes))
    bar_len = 24
    filled = int(pct * bar_len)
    empty = bar_len - filled
    return f"[green]{'█' * filled}[/green][dim]{'░' * empty}[/dim]"

def make_bandwidth_table(down_speed: float, up_speed: float, total_down: float, total_up: float) -> Panel:
    """Genera el panel dinámico para el Live display."""
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Canal de Tráfico", style="bold cyan", width=22)
    table.add_column("Velocidad Actual", style="bold white", width=30)
    table.add_column("Intensidad de Tráfico", width=30)
    table.add_column("Volumen Acumulado", style="yellow")

    down_meter = generate_meter(down_speed)
    up_meter = generate_meter(up_speed)

    table.add_row(
        "↓ Descarga (RX)",
        f"[bold bright_green]{format_speed(down_speed)}[/bold bright_green]",
        down_meter,
        format_bytes(total_down)
    )
    table.add_row(
        "↑ Subida (TX)",
        f"[bold bright_cyan]{format_speed(up_speed)}[/bold bright_cyan]",
        up_meter,
        format_bytes(total_up)
    )

    info_text = Text("\nPresione Ctrl+C para detener el monitoreo y regresar al menú...", style="dim white")

    return Panel(
        table,
        title="[bold bright_white]Monitor de Ancho de Banda en Vivo[/bold bright_white]",
        subtitle="[dim]Actualización cada 1 segundo[/dim]",
        border_style="bright_blue",
        box=box.ROUNDED
    )

def run_bandwidth_monitor(duration_seconds: int = None):
    """
    Ejecuta el bucle de muestreo de ancho de banda en tiempo real.
    """
    print_section_header("Monitor de Ancho de Banda en Tiempo Real", "Telemetría de consumo de red segundo a segundo")

    console.print("[dim]Iniciando muestreo de adaptadores de red... Presione [bold cyan]Ctrl+C[/bold cyan] para salir.[/dim]\n")

    t_prev = time.perf_counter()
    io_prev = psutil.net_io_counters()

    try:
        with Live(console=console, refresh_per_second=2) as live:
            count = 0
            while True:
                time.sleep(1.0)
                t_curr = time.perf_counter()
                io_curr = psutil.net_io_counters()

                dt = max(0.1, t_curr - t_prev)
                down_speed = (io_curr.bytes_recv - io_prev.bytes_recv) / dt
                up_speed = (io_curr.bytes_sent - io_prev.bytes_sent) / dt

                t_prev = t_curr
                io_prev = io_curr

                panel = make_bandwidth_table(down_speed, up_speed, io_curr.bytes_recv, io_curr.bytes_sent)
                live.update(panel)

                count += 1
                if duration_seconds and count >= duration_seconds:
                    break
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoreo de ancho de banda detenido por el usuario.[/yellow]")
