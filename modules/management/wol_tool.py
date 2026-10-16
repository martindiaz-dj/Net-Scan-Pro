"""
Herramienta Wake-on-LAN (WoL) para Encendido Remoto de Equipos.
Construye y envía tramas mágicas (Magic Packet) a través de difusión UDP.
"""
import re
import socket
from rich.table import Table
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, get_input
from core.utils import clean_mac, is_valid_mac

def send_magic_packet(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    """
    Construye y envía el Magic Packet (6 bytes 0xFF seguidos de 16 repeticiones de la MAC).
    """
    if not is_valid_mac(mac_address):
        print_error(f"La dirección MAC '{mac_address}' no tiene un formato válido (ej. AA:BB:CC:DD:EE:FF).")
        return False

    raw_hex = re.sub(r'[^0-9A-Fa-f]', '', mac_address)
    mac_bytes = bytes.fromhex(raw_hex)
    packet = b'\xff' * 6 + (mac_bytes * 16)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast_ip, port))
        sock.close()
        return True
    except Exception as e:
        print_error(f"Error al transmitir paquete WoL: {e}")
        return False

def wol_menu():
    """Submenú interactivo para Wake-on-LAN."""
    print_section_header("Encendido Remoto por Red (Wake-on-LAN)", "Envío de Magic Packet para encendido de PCs y servidores")

    console.print("[dim]Requiere que la tarjeta de red del equipo destino tenga habilitado WoL en BIOS/UEFI.[/dim]\n")
    
    target_mac = get_input("Ingrese la dirección MAC del equipo a encender (ej. 00:11:22:33:44:55)")
    if not target_mac:
        return

    broadcast_ip = get_input("Dirección IP de difusión (Broadcast)", default="255.255.255.255")
    port_str = get_input("Puerto UDP (habitualmente 9 o 7)", default="9")
    port = int(port_str) if port_str.isdigit() else 9

    with console.status("[bold cyan]Transmitiendo trama Magic Packet por broadcast...", spinner="dots"):
        success = send_magic_packet(target_mac, broadcast_ip=broadcast_ip, port=port)

    if success:
        formatted_mac = clean_mac(target_mac)
        table = Table(title="Detalle de Transmisión Wake-on-LAN", box=box.ROUNDED)
        table.add_column("Campo", style="bold cyan")
        table.add_column("Valor Transmitido", style="bold white")

        table.add_row("Dirección MAC Destino", formatted_mac)
        table.add_row("IP de Difusión", broadcast_ip)
        table.add_row("Puerto UDP", str(port))
        table.add_row("Tamaño de Trama", "102 Bytes (6x 0xFF + 16x MAC)")
        table.add_row("Estado de Envío", "[bold green]✔ Trama transmitida exitosamente[/bold green]")

        console.print()
        console.print(table)
        print_success(f"Paquete WoL enviado con éxito al host {formatted_mac}.")
