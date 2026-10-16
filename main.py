"""
==============================================================================
NETSCAN PRO - Consola de Administración, Diagnóstico y Seguridad de Redes
Punto de entrada principal con interfaz guiada por menús interactivos.
==============================================================================
"""
import sys
import os

# Asegurar que el directorio raíz del proyecto esté en el sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ui import (
    console,
    clear_screen,
    pause,
    print_banner,
    render_menu,
    print_section_header,
    print_info,
    print_success,
    print_error
)

# Importación de módulos funcionales
from modules.scanner.net_info import show_network_summary
from modules.diagnostics.ping_tool import ping_menu
from modules.diagnostics.traceroute_tool import traceroute_menu
from modules.diagnostics.dns_tool import dns_menu
from modules.scanner.arp_scanner import arp_menu
from modules.scanner.port_scanner import port_scanner_menu
from modules.subnetting.cidr_calc import cidr_menu
from modules.subnetting.vlsm_designer import vlsm_menu
from modules.monitoring.interfaces_tool import show_network_interfaces
from modules.monitoring.connections_tool import connections_menu
from modules.monitoring.bandwidth_monitor import run_bandwidth_monitor
from modules.management.wol_tool import wol_menu
from modules.management.ssl_tool import ssl_menu

def menu_diagnostics():
    """Submenú de Diagnóstico y Conectividad."""
    while True:
        clear_screen()
        print_banner()
        options = [
            ("1", "Ping Avanzado (ICMP & TCP Handshake con Jitter)"),
            ("2", "Trazado de Ruta (Traceroute con Resolución PTR)"),
            ("3", "Auditoría DNS & Benchmark de Servidores Públicos"),
        ]
        choice = render_menu("Módulo de Diagnóstico y Conectividad", options)
        
        if choice == "0":
            break
        elif choice == "q":
            sys.exit(0)
        elif choice == "1":
            clear_screen()
            ping_menu()
            pause()
        elif choice == "2":
            clear_screen()
            traceroute_menu()
            pause()
        elif choice == "3":
            clear_screen()
            dns_menu()
            pause()

def menu_scanner():
    """Submenú de Escaneo y Descubrimiento."""
    while True:
        clear_screen()
        print_banner()
        options = [
            ("1", "Telemetría del Host & Red WAN (IP pública, Gateway, DNS, ISP)"),
            ("2", "Escáner ARP LAN Ultrarrápido (Descubrimiento y Fabricantes OUI)"),
            ("3", "Escáner de Puertos TCP & Banner Grabbing (Servicios y Versiones)"),
        ]
        choice = render_menu("Módulo de Escaneo y Descubrimiento de Red", options)

        if choice == "0":
            break
        elif choice == "q":
            sys.exit(0)
        elif choice == "1":
            clear_screen()
            show_network_summary()
            pause()
        elif choice == "2":
            clear_screen()
            arp_menu()
            pause()
        elif choice == "3":
            clear_screen()
            port_scanner_menu()
            pause()

def menu_subnetting():
    """Submenú de Subnetting y Planificación IP."""
    while True:
        clear_screen()
        print_banner()
        options = [
            ("1", "Calculadora IPv4 / CIDR (Máscaras, Wildcard, Broadcast, Binario)"),
            ("2", "Diseñador de Subredes VLSM (Particionamiento Jerárquico por Hosts)"),
        ]
        choice = render_menu("Módulo de Planificación y Subnetting IP", options)

        if choice == "0":
            break
        elif choice == "q":
            sys.exit(0)
        elif choice == "1":
            clear_screen()
            cidr_menu()
            pause()
        elif choice == "2":
            clear_screen()
            vlsm_menu()
            pause()

def menu_monitoring():
    """Submenú de Monitoreo Local y SysAdmin."""
    while True:
        clear_screen()
        print_banner()
        options = [
            ("1", "Auditoría de Interfaces de Red (Estado UP/DOWN, MTU, Velocidad)"),
            ("2", "Sockets y Conexiones Activas (Netstat con Procesos y PIDs)"),
            ("3", "Monitor de Ancho de Banda en Vivo (Gráfico RX/TX Segundo a Segundo)"),
        ]
        choice = render_menu("Módulo de Monitoreo del Sistema y Tráfico", options)

        if choice == "0":
            break
        elif choice == "q":
            sys.exit(0)
        elif choice == "1":
            clear_screen()
            show_network_interfaces()
            pause()
        elif choice == "2":
            clear_screen()
            connections_menu()
            pause()
        elif choice == "3":
            clear_screen()
            run_bandwidth_monitor()
            pause()

def menu_management():
    """Submenú de Gestión y Herramientas Avanzadas."""
    while True:
        clear_screen()
        print_banner()
        options = [
            ("1", "Wake-on-LAN (Encendido Remoto por Magic Packet UDP)"),
            ("2", "Auditoría de Certificados SSL/TLS (Vigencia, CA, Dominios SAN)"),
        ]
        choice = render_menu("Módulo de Gestión y Herramientas Especiales", options)

        if choice == "0":
            break
        elif choice == "q":
            sys.exit(0)
        elif choice == "1":
            clear_screen()
            wol_menu()
            pause()
        elif choice == "2":
            clear_screen()
            ssl_menu()
            pause()

def main():
    """Punto de entrada principal con bucle de menú interactivo."""
    try:
        while True:
            clear_screen()
            print_banner()
            main_options = [
                ("1", "Diagnóstico de Conectividad (Ping ICMP/TCP, Traceroute, DNS)"),
                ("2", "Escaneo & Descubrimiento (ARP LAN, Puertos TCP, Banner Grabber)"),
                ("3", "Calculadora de Subredes & VLSM (CIDR, Wildcards, Segmentación)"),
                ("4", "Monitoreo Local & SysAdmin (Interfaces, Netstat con PIDs, Ancho de Banda)"),
                ("5", "Gestión & Auditoría Avanzada (Wake-on-LAN, Certificados SSL/TLS)"),
                ("6", "Resumen Ejecutivo de Conectividad (Quick Network Health Check)"),
            ]
            
            choice = render_menu("Menú Principal - NetScan Pro", main_options, can_go_back=False)

            if choice == "q":
                clear_screen()
                console.print("\n[bold cyan]Gracias por utilizar NetScan Pro Suite. ¡Hasta pronto![/bold cyan]\n")
                sys.exit(0)
            elif choice == "1":
                menu_diagnostics()
            elif choice == "2":
                menu_scanner()
            elif choice == "3":
                menu_subnetting()
            elif choice == "4":
                menu_monitoring()
            elif choice == "5":
                menu_management()
            elif choice == "6":
                clear_screen()
                show_network_summary()
                pause()
    except (KeyboardInterrupt, EOFError):
        clear_screen()
        console.print("\n[bold yellow]Sesión finalizada por el usuario.[/bold yellow]\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
