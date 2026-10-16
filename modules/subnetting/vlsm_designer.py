"""
Diseñador de Subredes de Longitud Variable (VLSM Designer).
Planificación y optimización de direccionamiento IP para arquitectos e ingenieros de red.
Optimizado para adaptarse limpiamente a consolas estándar (CMD / PowerShell) sin desbordamiento.
"""
import ipaddress
import math
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, print_warning, get_input

def design_vlsm(major_net_str: str, requirements: list[tuple[str, int]]):
    """
    Ejecuta el algoritmo de particionamiento VLSM.
    Ordena requerimientos de mayor a menor, calcula el bloque exponencial óptimo
    y verifica el espacio libre disponible en el bloque principal.
    """
    try:
        major = ipaddress.IPv4Network(major_net_str.strip(), strict=False)
    except ValueError as e:
        print_error(f"Red principal no válida: {e}")
        return

    # Ordenar por cantidad de hosts requeridos de forma descendente
    sorted_reqs = sorted(requirements, key=lambda x: x[1], reverse=True)
    
    current_int = int(major.network_address)
    major_end_int = int(major.broadcast_address)

    allocations = []
    total_allocated_ips = 0
    overflow = False

    for name, req_hosts in sorted_reqs:
        # Calcular bits de host necesarios: 2^h >= req_hosts + 2 (para red y broadcast)
        needed = req_hosts + 2
        h = max(2, math.ceil(math.log2(needed)))
        prefix = 32 - h
        block_size = 2 ** h

        # Alinear la dirección actual al límite de bloque si no lo estuviera
        if current_int % block_size != 0:
            current_int = ((current_int // block_size) + 1) * block_size

        if (current_int + block_size - 1) > major_end_int:
            overflow = True
            allocations.append({
                "name": name,
                "req": req_hosts,
                "error": "Espacio insuficiente en el bloque principal"
            })
            continue

        subnet = ipaddress.IPv4Network((current_int, prefix))
        netmask = subnet.netmask
        wildcard = ipaddress.IPv4Address(int(netmask) ^ 0xFFFFFFFF)
        first_host = subnet.network_address + 1
        last_host = subnet.broadcast_address - 1
        usable_hosts = block_size - 2
        wasted = usable_hosts - req_hosts

        allocations.append({
            "name": name,
            "req": req_hosts,
            "usable": usable_hosts,
            "subnet": str(subnet),
            "prefix": f"/{prefix}",
            "netmask": str(netmask),
            "wildcard": str(wildcard),
            "first_host": str(first_host),
            "last_host": str(last_host),
            "range": f"{first_host} -> {last_host}",
            "broadcast": str(subnet.broadcast_address),
            "wasted": wasted,
            "error": None
        })

        current_int += block_size
        total_allocated_ips += block_size

    # Construir tabla de resultados compacta y responsiva (se adapta a consolas de 80 columnas)
    table = Table(title=f"Planificación VLSM sobre Red Base: {major}", box=box.ROUNDED)
    table.add_column("Subred / VLAN", style="bold cyan")
    table.add_column("Hosts\nReq/Cap", style="yellow", justify="center")
    table.add_column("Red CIDR\nMáscara", style="bold white", no_wrap=True)
    table.add_column("Rango Asignable\n(Primero -> Último)", style="bright_yellow", no_wrap=True)
    table.add_column("Broadcast", style="magenta", no_wrap=True)

    for a in allocations:
        if a.get("error"):
            table.add_row(a["name"], str(a["req"]), "[red]ERROR[/red]", a["error"], "-")
        else:
            table.add_row(
                a["name"],
                f"{a['req']} / {a['usable']}",
                f"{a['subnet']}\n[dim]{a['netmask']}[/dim]",
                f"{a['first_host']}\n -> {a['last_host']}",
                a["broadcast"]
            )

    console.print()
    console.print(table)

    # Resumen de balance de direccionamiento
    major_capacity = major.num_addresses
    free_ips = max(0, major_capacity - total_allocated_ips)
    efficiency = (total_allocated_ips / major_capacity * 100) if major_capacity > 0 else 0

    summary_table = Table(title="Balance de Direccionamiento IP", box=box.SIMPLE)
    summary_table.add_column("Métrica", style="cyan")
    summary_table.add_column("Valor", style="bold white")

    summary_table.add_row("Capacidad Red Base", f"{major_capacity:,} direcciones ({major})")
    summary_table.add_row("Total IPs Asignadas en Bloques", f"{total_allocated_ips:,} direcciones")
    summary_table.add_row("Direcciones Libres Restantes", f"{free_ips:,} direcciones")
    summary_table.add_row("Tasa de Ocupación", f"{efficiency:.1f}%")

    console.print()
    console.print(summary_table)

    if overflow:
        print_error("¡Alerta!: La red base no tiene suficientes direcciones para cubrir todas las subredes solicitadas.")
    else:
        print_success("Diseño VLSM completado de manera óptima y sin solapamientos.")

    # Opción de desglose en fichas técnicas detalladas
    valid_allocs = [a for a in allocations if not a.get("error")]
    if valid_allocs:
        try:
            if Confirm.ask("\n¿Desea ver las fichas técnicas individuales detalladas?", default=False):
                console.print()
                for a in valid_allocs:
                    card_content = (
                        f"[bold cyan]Subred Asignada:[/bold cyan] [bold white]{a['subnet']}[/bold white]  |  "
                        f"[bold cyan]Máscara:[/bold cyan] {a['netmask']}  |  [bold cyan]Wildcard:[/bold cyan] {a['wildcard']}\n"
                        f"[bold yellow]Rango de Hosts:[/bold yellow] {a['first_host']} -> {a['last_host']}  |  "
                        f"[bold magenta]Broadcast:[/bold magenta] {a['broadcast']}\n"
                        f"[bold green]Capacidad:[/bold green] {a['usable']} hosts asignados  |  "
                        f"[dim]Requeridos: {a['req']} (Margen/Desperdicio: {a['wasted']} IPs)[/dim]"
                    )
                    console.print(Panel(card_content, title=f"[bold bright_white]{a['name']}[/bold bright_white]", border_style="cyan", box=box.ROUNDED))
        except (KeyboardInterrupt, EOFError):
            pass

def vlsm_menu():
    """Submenú interactivo para el Diseñador VLSM."""
    print_section_header("Diseñador de Subredes VLSM", "Segmentación jerárquica con asignación dinámica de máscaras")

    console.print("  [bold 1]1.[/bold 1] Cargar Plantilla de Ejemplo (Campus Corporativo: Ventas, Servidores, WiFi, WAN)")
    console.print("  [bold 2]2.[/bold 2] Crear Diseño Personalizado desde Cero")

    choice = get_input("Seleccione una opción", default="1")

    if choice == "1":
        major_net = "192.168.10.0/24"
        console.print(f"\n[cyan]Usando red base:[/cyan] [bold white]{major_net}[/bold white]")
        reqs = [
            ("VLAN-10 WiFi Invitados", 90),
            ("VLAN-20 Servidores & IT", 45),
            ("VLAN-30 Administración", 25),
            ("VLAN-40 VoIP / Telefonía", 12),
            ("Enlace WAN Router PTP", 2),
        ]
        design_vlsm(major_net, reqs)
    elif choice == "2":
        major_net = get_input("Ingrese la red principal a segmentar (ej. 172.16.0.0/20)", default="10.0.0.0/24")
        if not major_net:
            return

        reqs = []
        console.print("\n[bold cyan]Ingrese cada subred requerida (deje el nombre vacío para finalizar):[/bold cyan]")
        while True:
            name = get_input(f"Nombre de la subred #{len(reqs) + 1} (ej. Ventas, DMZ)")
            if not name:
                break
            hosts_str = get_input(f"Cantidad de hosts requeridos para '{name}'", default="20")
            hosts = int(hosts_str) if hosts_str.isdigit() else 20
            reqs.append((name, hosts))

        if not reqs:
            print_warning("No se ingresó ninguna subred.")
            return

        design_vlsm(major_net, reqs)
