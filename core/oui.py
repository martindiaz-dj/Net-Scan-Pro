"""
Resolución de Fabricante de Dispositivos por Dirección MAC (OUI Lookup).
Incluye base de datos local embebida para funcionamiento 100% offline y consulta opcional en línea.
"""
import re
import requests

# Base de datos local con los prefijos OUI más frecuentes en redes corporativas y hogareñas
OUI_DATABASE = {
    # Routers y Equipos de Red
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:C7": "Cisco Systems",
    "00:01:C9": "Cisco Systems",
    "00:07:0E": "Cisco Systems",
    "00:07:0F": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:1E:14": "Cisco Systems",
    "00:24:14": "Cisco Systems",
    "00:26:0B": "Cisco Systems",
    "00:27:0D": "Cisco Systems",
    "00:3A:9A": "Cisco Systems",
    "00:40:96": "Cisco Systems",
    "00:50:0F": "Cisco Systems",
    "00:50:50": "Cisco Systems",
    "00:60:2F": "Cisco Systems",
    "00:60:47": "Cisco Systems",
    "00:64:40": "Cisco Systems",
    "70:69:79": "Cisco Systems",
    "88:43:E1": "Cisco Systems",
    "A8:0C:0D": "Cisco Systems",
    "C4:72:95": "Cisco Systems",
    "CC:D5:39": "Cisco Systems",
    "F4:CF:E2": "Cisco Systems",

    # MikroTik
    "00:0C:42": "MikroTik",
    "04:B0:E7": "MikroTik",
    "08:55:31": "MikroTik",
    "18:FD:74": "MikroTik",
    "2C:C8:1B": "MikroTik",
    "48:8F:5A": "MikroTik",
    "64:D1:54": "MikroTik",
    "6C:3B:6B": "MikroTik",
    "74:4D:28": "MikroTik",
    "B8:69:F4": "MikroTik",
    "C4:AD:34": "MikroTik",
    "CC:2D:E0": "MikroTik",
    "D4:CA:6D": "MikroTik",
    "E4:8D:8C": "MikroTik",

    # Ubiquiti Networks
    "00:15:6D": "Ubiquiti Networks",
    "00:27:22": "Ubiquiti Networks",
    "04:18:D6": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "44:D9:E7": "Ubiquiti Networks",
    "68:D7:9A": "Ubiquiti Networks",
    "70:A7:41": "Ubiquiti Networks",
    "74:83:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "80:2A:A8": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "DC:9F:DB": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks",

    # TP-Link
    "00:25:86": "TP-Link Technologies",
    "14:CC:20": "TP-Link Technologies",
    "18:A6:F7": "TP-Link Technologies",
    "1C:3B:F3": "TP-Link Technologies",
    "30:B5:C2": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "60:A4:4C": "TP-Link Technologies",
    "74:DA:38": "TP-Link Technologies",
    "98:DA:C4": "TP-Link Technologies",
    "AC:84:C6": "TP-Link Technologies",
    "AC:3B:77": "TP-Link Technologies",
    "B0:95:75": "TP-Link Technologies",
    "C0:06:C3": "TP-Link Technologies",
    "C4:6E:7B": "TP-Link Technologies",
    "C8:3A:35": "TP-Link Technologies",
    "D8:07:B6": "TP-Link Technologies",
    "E4:C3:2A": "TP-Link Technologies",
    "F4:F2:6D": "TP-Link Technologies",

    # Huawei
    "00:18:82": "Huawei Technologies",
    "00:1E:10": "Huawei Technologies",
    "00:25:9E": "Huawei Technologies",
    "20:F3:A3": "Huawei Technologies",
    "28:6E:D4": "Huawei Technologies",
    "40:4D:8E": "Huawei Technologies",
    "70:7B:E8": "Huawei Technologies",
    "AC:E2:15": "Huawei Technologies",
    "F4:55:9C": "Huawei Technologies",

    # Netgear / D-Link
    "00:09:5B": "Netgear",
    "00:14:6C": "Netgear",
    "20:4E:7F": "Netgear",
    "A0:04:60": "Netgear",
    "C0:FF:D4": "Netgear",
    "00:05:5D": "D-Link",
    "00:15:E9": "D-Link",
    "14:D6:4D": "D-Link",
    "28:10:7B": "D-Link",

    # Intel (Tarjetas de Red PC/Laptops/Servidores)
    "00:13:02": "Intel Corporate",
    "00:15:00": "Intel Corporate",
    "00:1E:67": "Intel Corporate",
    "00:21:6A": "Intel Corporate",
    "34:13:E8": "Intel Corporate",
    "3C:F8:62": "Intel Corporate",
    "48:F1:7F": "Intel Corporate",
    "68:05:CA": "Intel Corporate",
    "70:1C:E7": "Intel Corporate",
    "80:86:F2": "Intel Corporate",
    "8C:85:90": "Intel Corporate",
    "A4:4C:C8": "Intel Corporate",
    "C4:23:60": "Intel Corporate",
    "E8:2A:44": "Intel Corporate",

    # Realtek
    "00:E0:4C": "Realtek Semiconductor",
    "2C:4D:54": "Realtek Semiconductor",
    "52:54:00": "Realtek / QEMU Virtual NIC",

    # Apple
    "00:03:93": "Apple Inc.",
    "00:0A:95": "Apple Inc.",
    "00:1C:B3": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "18:AF:61": "Apple Inc.",
    "28:CF:E9": "Apple Inc.",
    "34:36:3B": "Apple Inc.",
    "3C:07:54": "Apple Inc.",
    "40:98:AD": "Apple Inc.",
    "5C:96:9D": "Apple Inc.",
    "60:F8:1D": "Apple Inc.",
    "70:3E:AC": "Apple Inc.",
    "88:66:5A": "Apple Inc.",
    "9C:20:7B": "Apple Inc.",
    "A4:83:E7": "Apple Inc.",
    "AC:BC:32": "Apple Inc.",
    "BC:D1:1F": "Apple Inc.",
    "F0:18:98": "Apple Inc.",

    # Dell / HP / Lenovo
    "00:14:22": "Dell Inc.",
    "00:1E:4F": "Dell Inc.",
    "18:66:DA": "Dell Inc.",
    "24:B6:FD": "Dell Inc.",
    "74:86:7A": "Dell Inc.",
    "B8:85:84": "Dell Inc.",
    "F8:DB:88": "Dell Inc.",
    "00:08:02": "Hewlett Packard",
    "00:17:A4": "Hewlett Packard",
    "00:25:B3": "Hewlett Packard",
    "1C:C1:DE": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard",
    "70:5A:0F": "Hewlett Packard",
    "00:21:CC": "Lenovo",
    "54:EE:75": "Lenovo",

    # Virtualización y Nube (VMware, VirtualBox, Hyper-V, AWS, Docker)
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:1C:14": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "02:42:AC": "Docker Container Engine",

    # IoT, Domótica y Servidores Caseros
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Foundation",
    "24:6F:28": "Espressif Inc. (ESP32/ESP8266)",
    "30:AE:A4": "Espressif Inc. (ESP32/ESP8266)",
    "84:CC:A8": "Espressif Inc. (ESP32/ESP8266)",
    "A4:CF:12": "Espressif Inc. (ESP32/ESP8266)",
    "00:11:32": "Synology Inc.",
    "00:08:9B": "QNAP Systems",

    # Dispositivos Móviles y Otros
    "00:12:47": "Samsung Electronics",
    "08:EE:8B": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "48:44:F7": "Samsung Electronics",
    "88:30:8A": "Samsung Electronics",
    "B0:72:BF": "Samsung Electronics",
    "C8:19:F7": "Samsung Electronics",
    "40:B4:CD": "Amazon Technologies",
    "FC:65:DE": "Amazon Technologies",
    "F4:F5:DB": "Google LLC",
    "3C:5A:37": "Google LLC",
    "64:16:66": "Xiaomi Communications",
    "7C:49:EB": "Xiaomi Communications",
}

_CACHE = {}

def get_vendor(mac: str, allow_online: bool = False) -> str:
    """
    Obtiene el nombre del fabricante (Vendor) a partir de una dirección MAC.
    Busca primero en la base local (instantánea). Si no se encuentra y allow_online es True,
    puede consultar una API ligera.
    """
    if not mac:
        return "Desconocido"

    clean = re.sub(r'[^0-9A-Fa-f]', '', mac.upper())
    if len(clean) < 6:
        return "Inválida"

    oui_prefix = f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"

    # Búsqueda en cache de sesión
    if oui_prefix in _CACHE:
        return _CACHE[oui_prefix]

    # Búsqueda en base de datos local
    if oui_prefix in OUI_DATABASE:
        vendor = OUI_DATABASE[oui_prefix]
        _CACHE[oui_prefix] = vendor
        return vendor

    # Si está permitida la consulta en línea y no está en la base local
    if allow_online:
        try:
            url = f"https://api.macvendors.com/{clean[0:6]}"
            resp = requests.get(url, timeout=1.5)
            if resp.status_code == 200 and resp.text:
                vendor = resp.text.strip()
                _CACHE[oui_prefix] = vendor
                return vendor
        except Exception:
            pass

    _CACHE[oui_prefix] = "Genérico / No identificado"
    return "Genérico / No identificado"
