"""
Auditor de Certificados SSL/TLS y Cifrado Web.
Inspecciona fechas de expiración, autoridades de certificación (CA), dominios SAN y suite criptográfica.
"""
import ssl
import socket
from datetime import datetime, timezone
from rich.table import Table
from rich import box

from core.ui import console, print_section_header, print_info, print_error, print_success, print_warning, get_input

def extract_cert_fields(d_list) -> dict:
    """Convierte la estructura de tuplas anidadas del certificado en un diccionario legible."""
    res = {}
    if not d_list:
        return res
    for item in d_list:
        for key, val in item:
            res[key] = val
    return res

def inspect_ssl_certificate(host: str, port: int = 443, timeout: float = 3.5):
    """
    Establece un handshake TLS contra el objetivo, analiza el certificado X.509
    y evalúa el estado de vigencia y seguridad.
    """
    host = host.strip()
    if host.startswith("https://"):
        host = host[8:]
    elif host.startswith("http://"):
        host = host[7:]
    host = host.split('/')[0]

    console.print(f"[bold cyan]▶ Inspeccionando certificado SSL/TLS en [bold white]{host}:{port}[/bold white]...[/bold cyan]\n")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Permite inspeccionar certificados autofirmados o de prueba

    try:
        # Primero intentamos con verificación estándar para obtener cert completo
        std_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with std_ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    tls_ver = ss.version()
                    cipher_info = ss.cipher()
                    is_trusted = True
        except ssl.SSLCertVerificationError:
            # Si falla la validación (autofirmado o expirado), reconectar en modo permisivo
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    tls_ver = ss.version()
                    cipher_info = ss.cipher()
                    is_trusted = False
    except Exception as e:
        print_error(f"No se pudo completar el handshake SSL/TLS con {host}:{port}: {e}")
        return

    subject = extract_cert_fields(cert.get('subject', ()))
    issuer = extract_cert_fields(cert.get('issuer', ()))
    not_after_str = cert.get('notAfter')
    not_before_str = cert.get('notBefore')

    # Parsear fechas de expiración
    days_left = 0
    expire_status = "[dim]Desconocido[/dim]"
    if not_after_str:
        # Formato habitual: 'Dec  4 23:29:33 2026 GMT'
        try:
            exp_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = exp_date - now
            days_left = delta.days

            if days_left < 0:
                expire_status = f"[bold red]✖ EXPIRADO (Hace {abs(days_left)} días)[/bold red]"
            elif days_left < 15:
                expire_status = f"[bold red]⚠ CRÍTICO (Expira en {days_left} días)[/bold red]"
            elif days_left < 30:
                expire_status = f"[bold yellow]⚠ ALERTA (Expira en {days_left} días)[/bold yellow]"
            else:
                expire_status = f"[bold green]✔ Válido ({days_left} días restantes)[/bold green]"
        except Exception:
            pass

    # Dominios SAN (Subject Alternative Names)
    sans = []
    for typ, val in cert.get('subjectAltName', ()):
        if typ == "DNS":
            sans.append(val)
    sans_str = ", ".join(sans[:6]) + (f" (+{len(sans)-6} más)" if len(sans) > 6 else "") if sans else "Ninguno"

    table = Table(title=f"Auditoría Certificado X.509: {host}", box=box.ROUNDED)
    table.add_column("Atributo", style="bold cyan", width=26)
    table.add_column("Detalle", style="bold white")

    table.add_row("Nombre Común (CN)", subject.get('commonName', 'N/A'))
    table.add_row("Organización del Sujeto", subject.get('organizationName', 'N/A'))
    table.add_row("Autoridad Emisora (CA)", f"{issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
    table.add_row("Fecha de Emisión", not_before_str or "N/A")
    table.add_row("Fecha de Caducidad", not_after_str or "N/A")
    table.add_row("Estado de Vigencia", expire_status)
    table.add_row("Dominios Alternativos (SAN)", sans_str)
    table.add_row("Versión TLS Negociada", tls_ver or "N/A")
    table.add_row("Algoritmo / Cipher Suite", f"{cipher_info[0]} ({cipher_info[2]} bits)" if cipher_info else "N/A")
    table.add_row("Cadena de Confianza", "[green]✔ Válida / CA Reconocida[/green]" if is_trusted else "[yellow]⚠ No Confiable / Autofirmado[/yellow]")

    console.print()
    console.print(table)

def ssl_menu():
    """Submenú interactivo para Auditoría SSL."""
    print_section_header("Auditoría de Certificados SSL / TLS", "Inspección de caducidad, autoridad emisora y cifrado")

    host = get_input("Ingrese el dominio o IP HTTPS a auditar", default="google.com")
    if not host:
        return

    port_str = get_input("Puerto SSL/TLS", default="443")
    port = int(port_str) if port_str.isdigit() else 443

    inspect_ssl_certificate(host, port=port)
