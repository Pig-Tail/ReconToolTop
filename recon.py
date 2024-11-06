import subprocess
import os

# Archivos de entrada y salida
input_file = "subdominios.txt"  # Archivo con los subdominios
resolved_ips_file = "ips_resueltas.txt"  # Nuevo archivo para guardar los subdominios y sus IPs
open_ports_file = "puertos_abiertos.txt"
whois_ip_file = "whois_infraestructura.txt"
whois_domain_file = "whois_cloud.txt"

# Función para resolver subdominios a IPs
def resolve_subdomains_to_ips(subdomains):
    resolved_ips = []
    for subdomain in subdomains:
        # Resolver la IP usando nslookup o dnsx
        result = subprocess.run(["nslookup", subdomain], capture_output=True, text=True)
        if "Address:" in result.stdout:
            ip = result.stdout.split("Address:")[-1].strip()
            resolved_ips.append((subdomain, ip))
    return resolved_ips

# Función para verificar si una IP está activa
def check_if_ip_is_active(ip):
    response = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True)
    return "1 received" in response.stdout

# Crear un archivo con los dominios y las IPs activas
def save_active_ips_to_file(resolved_ips):
    with open(resolved_ips_file, 'w') as f:
        for subdomain, ip in resolved_ips:
            f.write(f"{subdomain},{ip}\n")
    print(f"[+] IPs activas guardadas en {resolved_ips_file}")

# Leer el archivo de IPs activas y extraer IPs y dominios
def load_ips_from_file():
    ips = []
    domain_ip_pairs = []
    if os.path.exists(resolved_ips_file) and os.path.getsize(resolved_ips_file) > 0:
        with open(resolved_ips_file, 'r') as f:
            for line in f:
                if ',' in line:
                    subdomain, ip = line.strip().split(',')
                    domain_ip_pairs.append((subdomain, ip))
                    ips.append(ip)
        print(f"[+] IPs y subdominios extraídos de {resolved_ips_file}")
    else:
        print(f"[!] Error: El archivo {resolved_ips_file} no existe o está vacío.")
        exit(1)
    return domain_ip_pairs

# Verificar si las IPs están activas
def get_active_ips(domain_ip_pairs):
    active_ips = []
    for subdomain, ip in domain_ip_pairs:
        if check_if_ip_is_active(ip):
            active_ips.append((subdomain, ip))
            print(f"[+] IP activa: {ip} ({subdomain})")
        else:
            print(f"[-] IP inactiva: {ip} ({subdomain})")
    return active_ips

# Escaneo de puertos específicos
def scan_ports_for_active_ips(active_ips):
    ports = "80,443,8080,8443,10443"  # Puertos web comunes
    for subdomain, ip in active_ips:
        result = subprocess.run(["nmap", "-p", ports, "--open", ip], capture_output=True, text=True)
        with open(open_ports_file, 'a') as f_ports:
            f_ports.write(f"Resultados de {ip} ({subdomain}):\n{result.stdout}\n")
    print(f"[+] Escaneo de puertos específicos completado, guardado en {open_ports_file}")

# Realizar whois en IPs y dominios, separando resultados por infraestructura propia y servicios en la nube
def whois_and_save_results(active_ips):
    for subdomain, ip in active_ips:
        # Whois para IP
        result_ip = subprocess.run(["whois", ip], capture_output=True, text=True)
        if any(keyword in result_ip.stdout.lower() for keyword in ["amazon", "cloudflare", "microsoft", "google"]):
            with open(whois_domain_file, 'a') as f_cloud:
                f_cloud.write(f"Whois de IP en infraestructura cloud ({ip}):\n{result_ip.stdout}\n")
        else:
            with open(whois_ip_file, 'a') as f_infra:
                f_infra.write(f"Whois de IP en infraestructura propia ({ip}):\n{result_ip.stdout}\n")

        # Whois para subdominio
        result_domain = subprocess.run(["whois", subdomain], capture_output=True, text=True)
        if any(keyword in result_domain.stdout.lower() for keyword in ["amazon", "cloudflare", "microsoft", "google"]):
            with open(whois_domain_file, 'a') as f_cloud:
                f_cloud.write(f"Whois de dominio en infraestructura cloud ({subdomain}):\n{result_domain.stdout}\n")
        else:
            with open(whois_ip_file, 'a') as f_infra:
                f_infra.write(f"Whois de dominio en infraestructura propia ({subdomain}):\n{result_domain.stdout}\n")

    print(f"[+] Whois completado. Resultados guardados en '{whois_domain_file}' para infraestructura cloud y '{whois_ip_file}' para infraestructura propia.")

# Leer la lista de subdominios desde un archivo
def load_subdomains_from_file():
    subdomains = []
    if os.path.exists(input_file) and os.path.getsize(input_file) > 0:
        with open(input_file, 'r') as f:
            subdomains = [line.strip() for line in f]
        print(f"[+] Subdominios extraídos de {input_file}")
    else:
        print(f"[!] Error: El archivo {input_file} no existe o está vacío.")
        exit(1)
    return subdomains

# 1. Leer subdominios desde un archivo
subdomains = load_subdomains_from_file()

# 2. Resolver subdominios a IPs
resolved_ips = resolve_subdomains_to_ips(subdomains)

# 3. Guardar IPs activas en un archivo
save_active_ips_to_file(resolved_ips)

# 4. Cargar IPs activas desde el archivo generado
domain_ip_pairs = load_ips_from_file()

# 5. Obtener solo las IPs activas
active_ips = get_active_ips(domain_ip_pairs)

# 6. Si hay IPs activas, proceder con escaneo de puertos y whois
if active_ips:
    scan_ports_for_active_ips(active_ips)
    whois_and_save_results(active_ips)
else:
    print("[!] No se encontraron IPs activas para realizar el escaneo de puertos o consultas whois.")
