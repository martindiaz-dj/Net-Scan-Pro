"""
Calculadora de Redes CIDR y Desglose IPv4 Exhaustivo.
Análisis de máscaras de subred, wildcard para ACLs de routers, rangos de hosts y representación binaria.
"""
import ipaddress
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, get_input

def get_ip_class(ip_obj: ipaddress.IPv4Address) -> str:
    """Determina la clase clásica (A, B, C, D, E) de una dirección IPv4."""
    first_octet = int(str(ip_obj).split('.')[0])
    if 1 <= first_octet <= 126:
        return "Clase A"
    elif first_octet == 127:
        return "Loopback (Clase A reservada)"
    elif 128 <= first_octet <= 191:
        return "Clase B"
    elif 192 <= first_octet <= 223:
        return "Clase C"
    elif 224 <= first_octet <= 239:
        return "Clase D (Multicast)"
    else:
        return "Clase E (Experimental / Investigación)"

def get_scope_type(ip_obj: ipaddress.IPv4Address) -> str:
    """Clasifica el ámbito de uso y RFC de la dirección IP."""
    if ip_obj.is_private:
        return "[bold yellow]Privada (RFC 1918 - Red Local / No Enrutable a Internet)[/bold yellow]"
    elif ip_obj.is_loopback:
        return "[bold cyan]Loopback (RFC 1122 - Interfaz Local 127.0.0.0/8)[/bold cyan]"
    elif ip_obj.is_link_local:
        return "[bold red]Enlace Local / APIPA (RFC 3927 - Autoconfiguración 169.254.0.0/16)[/bold red]"
    elif ip_obj.is_multicast:
        return "[bold magenta]Multicast (RFC 5771 - Difusión a Grupo 224.0.0.0/4)[/bold magenta]"
    elif ip_obj in ipaddress.IPv4Network("100.64.0.0/10"):
        return "[bold cyan]CGNAT (RFC 6598 - Proveedor de Internet / Carrier Grade NAT)[/bold cyan]"
    else:
        return "[bold green]Pública (Enrutable Globalmente en Internet)[/bold green]"

def to_binary_dotted(ip_int: int) -> str:
    """Convierte un entero IPv4 de 32 bits a cadena binaria dividida en octetos."""
    bin_str = f"{ip_int:032b}"
    return f"{bin_str[0:8]}.{bin_str[8:16]}.{bin_str[16:24]}.{bin_str[24:32]}"

def calculate_cidr(input_str: str):
    """Calcula y muestra todos los atributos de red a partir de una notación CIDR o IP + Máscara."""
    cleaned = input_str.strip().replace(" ", "/")
    try:
        # Permitir formatos como '192.168.1.10/255.255.255.0' o '192.168.1.10/24'
        if "/" in cleaned:
            interface = ipaddress.IPv4Interface(cleaned)
        else:
            interface = ipaddress.IPv4Interface(f"{cleaned}/24")
    except Exception as e:
        print_error(f"Error al interpretar la dirección o máscara: {e}")
        return

    ip = interface.ip
    network = interface.network
    netmask = network.netmask
    wildcard = ipaddress.IPv4Address(int(netmask) ^ 0xFFFFFFFF)
    broadcast = network.broadcast_address
    prefix = network.prefixlen

    # Hosts utilizables
    total_ips = network.num_addresses
    if prefix == 32:
        usable_hosts = 1
        first_host = ip
        last_host = ip
    elif prefix == 31:
        # RFC 3021: Enlaces punto a punto
        usable_hosts = 2
        first_host = network.network_address
        last_host = broadcast
    else:
        usable_hosts = max(0, total_ips - 2)
        first_host = network.network_address + 1
        last_host = broadcast - 1

    table = Table(title=f"Desglose de Red CIDR: {interface.with_prefixlen}", box=box.ROUNDED)
    table.add_column("Propiedad", style="bold cyan", width=26)
    table.add_column("Valor Decimal", style="bold white")
    table.add_column("Detalle / Equivalencias", style="yellow")

    table.add_row("Dirección IP Analizada", str(ip), f"Hex: 0x{int(ip):08X}")
    table.add_row("Dirección de Red (Network ID)", str(network.network_address), f"Bloque CIDR: /{prefix}")
    table.add_row("Máscara de Subred", str(netmask), f"Bits de Red: {prefix} | Bits de Host: {32 - prefix}")
    table.add_row("Máscara Wildcard (Inversa)", str(wildcard), "Para ACLs y OSPF en Cisco/Routers")
    table.add_row("Dirección de Difusión (Broadcast)", str(broadcast), "Destino para tramas broadcast")
    table.add_row("Primer Host Utilizable", str(first_host), "IP mínima asignable a un equipo")
    table.add_row("Último Host Utilizable", str(last_host), "IP máxima asignable a un equipo")
    table.add_row("Rango Asignable de Hosts", f"{first_host}  ➡  {last_host}", f"{usable_hosts:,} direcciones válidas")
    table.add_row("Total de IPs en el Bloque", f"{total_ips:,}", f"2^{32 - prefix} direcciones totales")
    table.add_row("Clasificación de Red", get_ip_class(ip), "Clasificación con clase original")
    table.add_row("Ámbito / Tipo de Dirección", get_scope_type(ip), "Regulación IANA / RFC")

    console.print()
    console.print(table)

    # Tabla pedagógica binaria
    bin_table = Table(title="Representación Binaria a Nivel de Octeto", box=box.SIMPLE_HEAVY)
    bin_table.add_column("Elemento", style="cyan", width=20)
    bin_table.add_column("Octeto 1", style="white", justify="center")
    bin_table.add_column("Octeto 2", style="white", justify="center")
    bin_table.add_column("Octeto 3", style="white", justify="center")
    bin_table.add_column("Octeto 4", style="white", justify="center")

    ip_b = to_binary_dotted(int(ip)).split('.')
    mask_b = to_binary_dotted(int(netmask)).split('.')
    net_b = to_binary_dotted(int(network.network_address)).split('.')
    wild_b = to_binary_dotted(int(wildcard)).split('.')

    bin_table.add_row("Dirección IP", ip_b[0], ip_b[1], ip_b[2], ip_b[3])
    bin_table.add_row("Máscara de Red", mask_b[0], mask_b[1], mask_b[2], mask_b[3])
    bin_table.add_row("Dirección de Red", net_b[0], net_b[1], net_b[2], net_b[3])
    bin_table.add_row("Wildcard Inversa", wild_b[0], wild_b[1], wild_b[2], wild_b[3])

    console.print()
    console.print(bin_table)

def cidr_menu():
    """Submenú interactivo para la Calculadora CIDR."""
    print_section_header("Calculadora de Subredes IPv4 / CIDR", "Desglose técnico de máscaras, wildcard, broadcast y rangos de hosts")
    
    console.print("[dim]Ejemplos admitidos: 192.168.10.45/27, 10.0.0.1/16, 172.16.5.10 255.255.240.0[/dim]\n")
    user_input = get_input("Ingrese la dirección IP con prefijo CIDR o máscara", default="192.168.1.100/24")
    
    if user_input:
        calculate_cidr(user_input)
