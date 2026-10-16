"""
Auditoría de Adaptadores e Interfaces de Red Locales.
Inspección de estado UP/DOWN, velocidad de enlace, MTU, estadísticas de tráfico y direcciones asignadas.
"""
import socket
import psutil
from rich.table import Table
from rich import box

from core.ui import console, print_section_header, print_info, print_error
from core.utils import format_bytes

def show_network_interfaces():
    """Recopila y presenta el estado de todas las interfaces de red del equipo."""
    print_section_header("Interfaces y Adaptadores de Red", "Parámetros de Capa 1, 2 y 3 de Adaptadores Locales")

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)

    table = Table(title="Adaptadores de Red del Sistema", box=box.ROUNDED)
    table.add_column("Interfaz", style="bold cyan")
    table.add_column("Estado", style="bold", justify="center")
    table.add_column("Velocidad / MTU", style="yellow")
    table.add_column("Dirección MAC", style="dim white", min_width=17)
    table.add_column("IPv4 Asignada", style="bold white", min_width=16)
    table.add_column("Tráfico Acumulado (RX / TX)", style="green")

    for iface_name, addr_list in addrs.items():
        # Estadísticas básicas
        st = stats.get(iface_name)
        status_str = "[green]UP (Activa)[/green]" if (st and st.isup) else "[dim red]DOWN[/dim red]"
        speed_str = f"{st.speed} Mbps" if (st and st.speed > 0) else "N/A"
        mtu_str = f"MTU: {st.mtu}" if (st and st.mtu) else ""
        speed_mtu = f"{speed_str} | {mtu_str}".strip(" | ")

        # Direcciones
        mac_addr = "-"
        ipv4_addr = "-"
        ipv6_addr = "-"

        for a in addr_list:
            if a.family == psutil.AF_LINK or getattr(socket, 'AF_PACKET', -1) == a.family or a.family == 17 or getattr(a, 'family', None) == -1:
                mac_addr = a.address.upper()
            elif a.family == socket.AF_INET:
                ipv4_addr = f"{a.address}/{a.netmask}" if a.netmask else a.address
            elif a.family == socket.AF_INET6:
                ipv6_addr = a.address

        # Si MAC sigue en blanco en Windows, psutil usa familia -1 o af_link
        if mac_addr == "-":
            for a in addr_list:
                if len(a.address.replace('-', ':').split(':')) == 6:
                    mac_addr = a.address.upper()
                    break

        # Contadores de tráfico
        io = io_counters.get(iface_name)
        traffic_str = "-"
        if io:
            traffic_str = f"↓ {format_bytes(io.bytes_recv)} | ↑ {format_bytes(io.bytes_sent)}"

        # Omitir interfaces de loopback si no están en uso y no tienen IP asignada
        if ipv4_addr == "-" and mac_addr == "-" and not (st and st.isup):
            continue

        table.add_row(iface_name, status_str, speed_mtu, mac_addr, ipv4_addr, traffic_str)

    console.print(table)
