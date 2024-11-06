# ReconToolTop
Recon de subdominios cargados de una lista con algo de magia

Tool escrita en python que en base a una lista de subdominios (txt) resuelve las ips, verifica si las ips están vivas, realiza escaneo de puertos web y realiza consultas whois para comprobar si las ips están en su infraestructura o están en el cloud o en un proveedor externo

Cargar subdominios: El script lee la lista de subdominios desde un archivo (en este caso subdominios.txt).

Resolver subdominios: Usa nslookup para resolver las IPs asociadas a cada subdominio.

Verificar IPs activas: Se hace un ping para verificar si las IPs están activas.

Guardar IPs activas: Si la IP está activa, se guarda en el archivo ips_resueltas.txt con el formato subdominio,IP.

Escaneo de puertos específicos: Se usa nmap para escanear puertos web comunes como 80, 443, 8080, 8443, 10443.

Whois de dominios e IPs: Se realiza un whois tanto de las IPs como de los subdominios y se guarda la información separada entre infraestructura propia y en la nube (Amazon, Microsoft, Google, Cloudflare, etc.).

Archivos de salida:

- ips_resueltas.txt: Guarda subdominios y sus IPs activas.
- puertos_abiertos.txt: Guarda los resultados de escaneo de puertos.
- whois_infraestructura.txt: Guarda la información de whois para IPs de infraestructura propia.
- whois_cloud.txt: Guarda la información de whois para IPs de infraestructura en la nube.
