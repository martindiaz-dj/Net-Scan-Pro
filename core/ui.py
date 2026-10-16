"""
Interfaz de Consola de Alta Definición (Rich CLI) para NetScan Pro.
Provee banners, tablas, paneles, menús interactivos y alertas visuales.
"""
import os
import sys

# Asegurar soporte de codificación UTF-8 en consolas Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm

console = Console(force_terminal=True)

BANNER_TEXT = r"""
  ██████╗ ███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
  ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
  ██████╔╝█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
  ██╔══██╗██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
  ██║  ██║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║    ██║     ██║  ██║╚██████╔╝
  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
"""

def clear_screen():
    """Limpia la pantalla de la consola de forma compatible con Windows y Linux."""
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    """Pausa la ejecución hasta que el usuario presione Enter."""
    console.print("\n[dim]Presione [bold cyan]Enter[/bold cyan] para continuar...[/dim]", end="")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass

def print_banner():
    """Muestra el banner principal de la suite con información de versión y estado."""
    clear_screen()
    banner = Text(BANNER_TEXT, style="bold cyan")
    subtext = Text("Suite Profesional de Administración, Diagnóstico y Seguridad de Redes\n", style="bold white")
    subtext.append("Plataforma: Python 3 | Entorno: Windows NetOps | Modo: Menú Interactivo", style="dim cyan")
    
    panel = Panel(
        Text.assemble(banner, "\n", subtext, justify="center"),
        border_style="bright_blue",
        box=box.DOUBLE,
        padding=(0, 2)
    )
    console.print(panel)

def print_section_header(title: str, subtitle: str = ""):
    """Imprime un encabezado de sección estilizado."""
    header_text = Text(f" {title.upper()} ", style="bold black on bright_cyan")
    if subtitle:
        content = Text.assemble(header_text, "\n", Text(subtitle, style="italic white"))
    else:
        content = header_text
    console.print()
    console.print(Panel(content, border_style="cyan", box=box.ROUNDED))
    console.print()

def print_success(message: str):
    console.print(f"[bold green][+] [ÉXITO][/bold green] {message}")

def print_error(message: str):
    console.print(f"[bold red][X] [ERROR][/bold red] {message}")

def print_warning(message: str):
    console.print(f"[bold yellow][!] [AVISO][/bold yellow] {message}")

def print_info(message: str):
    console.print(f"[bold cyan][*] [INFO][/bold cyan] {message}")

def render_menu(title: str, options: list[tuple[str, str]], can_go_back: bool = True) -> str:
    """
    Renderiza un menú elegante con opciones numéricas.
    options es una lista de tuplas: [("1", "Descripción"), ("2", "Descripción 2")]
    """
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2), expand=False)
    table.add_column("Key", style="bold bright_cyan", justify="right")
    table.add_column("Option", style="bold white")

    for key, desc in options:
        table.add_row(f"[{key}]", desc)

    if can_go_back:
        table.add_row("[0]", "[dim yellow]<-- Volver al menú anterior[/dim yellow]")
    table.add_row("[q]", "[dim red][X] Salir de la aplicación[/dim red]")

    panel = Panel(
        table,
        title=f"[bold bright_white]{title}[/bold bright_white]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(1, 3)
    )
    console.print(panel)

    valid_keys = [k.lower() for k, _ in options]
    if can_go_back:
        valid_keys.append("0")
    valid_keys.append("q")

    while True:
        try:
            choice = Prompt.ask("[bold cyan]Seleccione una opción[/bold cyan]", default="1" if options else "q")
            choice = choice.strip().lower()
            if choice in valid_keys:
                return choice
            print_error(f"Opción inválida '{choice}'. Ingrese una de las opciones válidas: {', '.join(valid_keys)}")
        except (KeyboardInterrupt, EOFError):
            return "q"

def get_input(prompt_text: str, default: str = None, validator=None) -> str:
    """Solicita una entrada de usuario con soporte para valor por defecto y validación opcional."""
    while True:
        try:
            if default:
                val = Prompt.ask(f"[bold white]{prompt_text}[/bold white]", default=default)
            else:
                val = Prompt.ask(f"[bold white]{prompt_text}[/bold white]")
            val = val.strip()
            if validator:
                if validator(val):
                    return val
                print_error(f"Entrada inválida '{val}'. Por favor verifique el formato.")
            else:
                return val
        except (KeyboardInterrupt, EOFError):
            return ""
