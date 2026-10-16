"""
Exportador de Reportes de Auditoría de Red.
Genera informes en formatos JSON y CSV con marca de tiempo para documentación y cumplimiento.
"""
import os
import json
import csv
from datetime import datetime
from core.ui import console, print_success, print_error, print_info

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "reports")

def ensure_reports_dir():
    """Asegura que el directorio de reportes exista en el proyecto."""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)

def export_scan_results(scan_type: str, data: dict, format_type: str = "json") -> str:
    """
    Exporta datos de escaneo a disco con marca de tiempo.
    scan_type: 'arp_scan', 'port_scan', etc.
    """
    ensure_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{scan_type}_{timestamp}.{format_type}"
    filepath = os.path.join(REPORTS_DIR, filename)

    payload = {
        "report_type": scan_type,
        "generated_at": datetime.now().isoformat(),
        "tool": "NetScan Pro Suite",
        "data": data
    }

    try:
        if format_type == "json":
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4, ensure_ascii=False)
        elif format_type == "csv":
            # Para ARP scans o listas planas
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if scan_type == "arp_scan":
                    writer.writerow(["IP", "MAC", "Vendor", "Hostname"])
                    for h in data.get("hosts", []):
                        writer.writerow([h.get("ip"), h.get("mac"), h.get("vendor"), h.get("hostname")])
                elif scan_type == "port_scan":
                    writer.writerow(["Port", "Service", "Description", "Banner"])
                    for p in data.get("open_ports", []):
                        writer.writerow([p.get("port"), p.get("service"), p.get("description"), p.get("banner")])

        print_success(f"Reporte exportado exitosamente:")
        console.print(f"  [cyan]Archivo:[/cyan] [bold white]{filepath}[/bold white]")
        return filepath
    except Exception as e:
        print_error(f"Error al escribir el archivo de reporte: {e}")
        return ""
