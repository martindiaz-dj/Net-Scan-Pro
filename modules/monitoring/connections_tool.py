"""
Monitor de Conexiones Activas y Sockets de Red (Netstat Enriquecido).
Muestra sockets TCP/UDP abiertos, estados de conexión y vincula cada socket con su proceso y PID correspondiente.
"""
import socket
import psutil
from rich.table import Table
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_warning, get_input

def get_process_name_safe(pid: int) -> str:
    """Obtiene el nombre del ejecutable a partir de un PID de forma segura."""
    if not pid or pid < 0:
        return "Sistema / Kernel"
    try:
        p = psutil.Process(pid)
        return p.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"PID {pid} (Restringido)"
    except Exception:
        return f"PID {pid}"

def list_active_connections(filter_status: str = None, filter_query: str = None, limit: int = 50):
    """
    Obtiene la lista de conexiones activas en el equipo local,
    aplica filtros de estado o término de búsqueda y las presenta en una tabla.
    """
    with console.status("[bold cyan]Consultando sockets y tablas de estado TCP/UDP...", spinner="dots"):
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception as e:
            print_error(f"Error al obtener sockets de red (¿requiere permisos de Administrador?): {e}")
            return

    filtered = []
    for c in conns:
        # Filtro de estado (ej. LISTEN, ESTABLISHED)
        if filter_status and c.status != filter_status:
            continue

        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-:-"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-:-"
        status = c.status if c.status else "NONE"
        proc_name = get_process_name_safe(c.pid)
        pid_str = str(c.pid) if c.pid else "-"

        # Filtro de texto (búsqueda en puerto, ip o nombre de proceso)
        if filter_query:
            q = filter_query.lower()
            if q not in laddr.lower() and q not in raddr.lower() and q not in proc_name.lower() and q not in pid_str:
                continue

        filtered.append({
            "proto": proto,
            "laddr": laddr,
            "raddr": raddr,
            "status": status,
            "pid": pid_str,
            "proc": proc_name
        })

    table = Table(
        title=f"Conexiones de Red Activas (Mostrando {min(len(filtered), limit)} de {len(filtered)})",
        box=box.ROUNDED
    )
    table.add_column("Proto", style="bold cyan", justify="center")
    table.add_column("Dirección Local", style="bold white")
    table.add_column("Dirección Remota", style="white")
    table.add_column("Estado del Socket", style="yellow")
    table.add_column("PID", style="dim white", justify="right")
    table.add_column("Proceso Asociado", style="bold green")

    for item in filtered[:limit]:
        status_styled = item["status"]
        if item["status"] == "LISTEN":
            status_styled = "[bold green]LISTEN (A la escucha)[/bold green]"
        elif item["status"] == "ESTABLISHED":
            status_styled = "[bold cyan]ESTABLISHED (Activa)[/bold cyan]"
        elif item["status"] in ("TIME_WAIT", "CLOSE_WAIT"):
            status_styled = f"[dim yellow]{item['status']}[/dim yellow]"

        table.add_row(
            item["proto"],
            item["laddr"],
            item["raddr"],
            status_styled,
            item["pid"],
            item["proc"]
        )

    console.print()
    if filtered:
        console.print(table)
    else:
        print_warning("No se encontraron conexiones con los filtros seleccionados.")

def connections_menu():
    """Submenú interactivo para el Monitor de Conexiones Activas."""
    print_section_header("Monitor de Conexiones Activas (Netstat)", "Auditoría de puertos en escucha, conexiones salientes y procesos")

    console.print("  [bold 1]1.[/bold 1] Ver Todos los Puertos a la Escucha (LISTEN - Servicios Locales)")
    console.print("  [bold 2]2.[/bold 2] Ver Conexiones Establecidas (ESTABLISHED - Sesiones Activas)")
    console.print("  [bold 3]3.[/bold 3] Ver Todas las Conexiones (Sin filtro)")
    console.print("  [bold 4]4.[/bold 4] Buscar por Puerto, IP o Nombre de Proceso (ej: 443, chrome.exe)")

    choice = get_input("Seleccione una opción", default="1")

    if choice == "1":
        list_active_connections(filter_status="LISTEN")
    elif choice == "2":
        list_active_connections(filter_status="ESTABLISHED")
    elif choice == "3":
        list_active_connections()
    elif choice == "4":
        query = get_input("Ingrese término a buscar (puerto, IP o proceso)")
        if query:
            list_active_connections(filter_query=query)
