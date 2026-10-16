# NetScan Pro - Suite de Administración y Diagnóstico de Redes

**NetScan Pro** es una herramienta de consola interactiva en Python diseñada específicamente para **Administradores de Redes (NetAdmins)**, **Ingenieros de Infraestructura** y **SysAdmins**. Cubre desde diagnósticos elementales de conectividad hasta tareas avanzadas de auditoría, planificación de direccionamiento IP y monitoreo en tiempo real.

---

## Características Principales

### 1. Diagnóstico de Conectividad & Ping Avanzado
- **Ping ICMP Estándar:** Medición de latencia mínima, máxima, promedio y cálculo del porcentaje de paquetes perdidos.
- **Ping TCP Handshake (SYN/ACK):** Permite verificar la disponibilidad de servicios específicos (HTTP 80, HTTPS 443, SSH 22, RDP 3389) eludiendo bloqueos de firewall que descartan paquetes ICMP Echo Request. Incluye cálculo de **Jitter (varianza de retardo)**.
- **Trazado de Ruta (Traceroute):** Mapeo de saltos de red (*hops*) con latencias RTT en tiempo real y resolución inversa de nombres (PTR/FQDN) para cada nodo intermedio.
- **Auditoría DNS Integral:** Consulta de registros de zona (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`) y búsqueda inversa PTR.
- **Benchmark de Resolvers DNS:** Comparación de tiempos de respuesta en milisegundos entre Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), Quad9 (`9.9.9.9`), OpenDNS (`208.67.222.222`) y el DNS local del sistema.

### 2. Escaneo y Descubrimiento de Red (LAN & Puertos)
- **Telemetría de Red y WAN:** Resumen ejecutivo con nombre de equipo, IP local de ruta saliente, dirección y MAC de la puerta de enlace predeterminada, servidores DNS, y dirección IP pública (WAN) con ISP, ASN y geolocalización aproximada.
- **Escáner ARP LAN Ultrarrápido:** Descubrimiento de hosts activos en subredes locales mediante la API nativa de Windows (`iphlpapi.SendARP`) con multithreading (`ThreadPoolExecutor`). **No requiere instalar controladores Npcap ni WinPcap**.
- **Identificación de Fabricantes (OUI Database):** Detección automática del fabricante del hardware (Cisco, MikroTik, Ubiquiti, TP-Link, Intel, Apple, HP, Dell, VMware, etc.) a partir de la dirección MAC.
- **Escáner de Puertos TCP Multihilo:**
  - Perfiles predefinidos: Top 25 Puertos Administrativos Críticos, Top 100 Puertos Más Comunes, Puertos Well-Known (1-1024), Rango personalizado y Auditoría Completa (1-65535).
  - **Banner Grabbing:** Extracción de firmas de versión en servicios web (`Server:` header en HTTP/HTTPS) y cabeceras de bienvenida en SSH, FTP y SMTP.

### 3. Calculadora de Subredes & Planificación IP (Subnetting)
- **Calculadora CIDR Exhaustiva:**
  - Dirección de red (Network ID) y dirección de broadcast.
  - Máscara de subred en formato decimal y binario.
  - **Máscara Wildcard (Inversa):** Cálculo inmediato para listas de control de acceso (ACLs) y protocolos de enrutamiento OSPF en routers Cisco/MikroTik.
  - Rango completo de hosts utilizables y conteo total de direcciones.
  - Clasificación con clase (Clase A, B, C, D, E) y ámbito regulatorio (Privada RFC 1918, CGNAT RFC 6598, APIPA RFC 3927, Loopback, Pública).
  - Alineación pedagógica en binario por octetos.
- **Diseñador de Subredes VLSM (Variable Length Subnet Masking):**
  - Segmentación jerárquica y eficiente a partir de una red mayor.
  - Asignación dinámica de bloques en base al requerimiento de hosts de cada departamento/VLAN.
  - Cálculo de desperdicio de direcciones y balance de ocupación de la red base.

### 4. Monitoreo Local, Conexiones & SysAdmin
- **Auditoría de Interfaces de Red:** Inspección de adaptadores físicos y virtuales, estado (`UP`/`DOWN`), velocidad negociada (ej. 1 Gbps), MTU, direcciones IPv4/IPv6 asignadas y contadores de tráfico acumulado (bytes/paquetes RX/TX).
- **Monitor de Conexiones Activas (Netstat Enriquecido):** Visualización de sockets TCP/UDP con identificación del estado (`LISTEN`, `ESTABLISHED`, `TIME_WAIT`) y mapeo directo al **PID** y **nombre del ejecutable/proceso** correspondiente (ej. `chrome.exe`, `python.exe`, `svchost.exe`).
- **Monitor de Ancho de Banda en Tiempo Real:** Muestreo segundo a segundo de tasas de descarga y subida con indicadores gráficos visuales dinámicos.

### 5. Herramientas Especiales de Red
- **Wake-on-LAN (WoL):** Construcción y transmisión de tramas *Magic Packet* UDP (puertos 9 y 7) para el encendido remoto de estaciones de trabajo, servidores y dispositivos NAS.
- **Auditoría de Certificados SSL/TLS:** Análisis de vigencia de certificados X.509 en servicios HTTPS, días restantes antes de caducar con semáforo de alertas (Crítico / Alerta / Válido), autoridad certificadora (CA), dominios alternativos (SAN), versión de TLS negociada y suite criptográfica.

### 6. Exportación de Reportes
- Posibilidad de exportar resultados de inventarios de red (ARP) y auditorías de puertos abiertos a archivos estructurados **JSON** y **CSV** con marca de tiempo en la carpeta `reports/`.

---

## Estructura del Proyecto

```
ProyectoRedScan/
│
├── main.py                     # Punto de entrada de la consola interactiva con Rich
├── netscan.bat                 # Lanzador rápido de un clic para Windows
├── requirements.txt            # Dependencias del proyecto
├── test_suite.py               # Suite de pruebas unitarias automatizadas
├── README.md                   # Documentación técnica
│
├── core/                       # Núcleo del sistema y utilidades
│   ├── __init__.py
│   ├── ui.py                   # Banners, menús interactivos, temas y alertas Rich
│   ├── utils.py                # Validaciones (IP, CIDR, MAC, puertos) y formateo de bytes/velocidad
│   └── oui.py                  # Base de datos y resolución de fabricantes por MAC (OUI)
│
├── modules/                    # Módulos funcionales organizados por dominio
│   ├── __init__.py
│   ├── diagnostics/            # Ping ICMP/TCP, Traceroute, Auditoría DNS
│   │   ├── ping_tool.py
│   │   ├── traceroute_tool.py
│   │   └── dns_tool.py
│   ├── scanner/                # Telemetría de red, Escáner ARP y Escáner de Puertos
│   │   ├── net_info.py
│   │   ├── arp_scanner.py
│   │   └── port_scanner.py
│   ├── subnetting/             # Calculadora CIDR y Diseñador VLSM
│   │   ├── cidr_calc.py
│   │   └── vlsm_designer.py
│   ├── monitoring/             # Interfaces, Netstat con PIDs y Ancho de Banda en vivo
│   │   ├── interfaces_tool.py
│   │   ├── connections_tool.py
│   │   └── bandwidth_monitor.py
│   ├── management/             # Wake-on-LAN y Auditor SSL/TLS
│   │   ├── wol_tool.py
│   │   └── ssl_tool.py
│   └── report/                 # Exportación a JSON y CSV
│       └── exporter.py
│
└── reports/                    # Directorio de auditorías y reportes generados
```

---

## Instalación y Requisitos

### Requisitos Previos
- Python 3.10 o superior (probado en Python 3.14).
- Sistema Operativo Windows (con soporte nativo para `iphlpapi.SendARP`).

### Instalación de Dependencias
Abra su terminal o PowerShell en el directorio del proyecto y ejecute:

```powershell
pip install -r requirements.txt
```

---

## Modo de Uso

### 1. Ejecución Directa
Ejecute el script principal de Python:

```powershell
python main.py
```

O simplemente haga doble clic en el archivo [netscan.bat](file:///c:/Users/Martin/Desktop/ProyectoRedScan/netscan.bat) para abrir la consola directamente.

### 2. Navegación en el Menú
El menú está diseñado con opciones numéricas guiadas:
- Ingrese el número de la opción deseada y presione `Enter`.
- Para volver al menú anterior, ingrese `0`.
- Para salir en cualquier momento, ingrese `q` o presione `Ctrl+C`.

---

## Pruebas Automatizadas

El proyecto incluye una suite de pruebas para verificar validaciones, cálculos matemáticos de subredes, resolución OUI y exportación de reportes:

```powershell
python test_suite.py
```
