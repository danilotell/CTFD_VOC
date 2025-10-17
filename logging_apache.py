import logging
import logging.handlers
import time
import os
import socket # Necesario para definir el socket de Syslog

# --- CONFIGURACIÓN REQUERIDA ---
SIEM_HOST = '10.0.0.25'  # Reemplaza con la IP real de tu SIEM o colector
SIEM_PORT = 514          # Puerto Syslog estándar (puede variar)
PROTOCOL = 'UDP'         # Elige el protocolo: 'UDP' o 'TCP'
# Define la ruta del archivo de logs. 
# Si esta variable es una cadena vacía (''), el script usará la lista de logs de SIMULACIÓN.
# Si NO está vacía (ej. '/var/log/app.log'), el script leerá ese archivo línea por línea.
LOG_FILE_PATH = ''       # <--- ¡AQUÍ ESTÁ LA NUEVA OPCIÓN!

# ------------------------------

# Mapeo de protocolo a tipo de socket
PROTOCOL_MAP = {
    'TCP': socket.SOCK_STREAM,
    'UDP': socket.SOCK_DGRAM
}

# Ejemplos de logs de Apache (usados solo si LOG_FILE_PATH está vacío)
LOG_LINES = [
    '192.168.1.10 - - [16/Oct/2025:19:15:30 -0500] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.5 - user_attempt [16/Oct/2025:19:16:00 -0500] "POST /login.php HTTP/1.1" 401 512 "http://ejemplo.com/login" "curl/7.84.0"',
    '203.0.113.44 - - [16/Oct/2025:19:16:35 -0500] "GET /admin/config.bak HTTP/1.1" 404 291 "-" "masscan/1.3"',
]


def setup_syslog_handler(protocol):
    """Configura el handler para enviar logs por Syslog (UDP o TCP)."""
    
    if protocol.upper() not in PROTOCOL_MAP:
        raise ValueError("Protocolo no válido. Debe ser 'TCP' o 'UDP'.")

    socket_type = PROTOCOL_MAP[protocol.upper()]
    
    syslog_handler = logging.handlers.SysLogHandler(
        address=(SIEM_HOST, SIEM_PORT),
        facility=logging.handlers.SysLogHandler.LOG_LOCAL0, 
        socktype=socket_type
    )
    
    formatter = logging.Formatter('%(message)s')
    syslog_handler.setFormatter(formatter)

    logger = logging.getLogger('LogSender')
    logger.setLevel(logging.INFO)
    logger.addHandler(syslog_handler)
    return logger

def get_logs_to_send(log_path):
    """
    Decide si usar la lista de simulación o leer un archivo.
    Retorna una lista de logs (simulación) o un generador/iterable (archivo).
    """
    if log_path:
        # Modo Archivo
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Archivo no encontrado en la ruta: {log_path}")
        
        print(f"\nUsando el modo ARCHIVO: Leyendo logs desde '{log_path}'.")
        # Abrimos el archivo y devolvemos las líneas. No usamos 'tail -f' aquí, 
        # solo leemos el archivo completo una vez.
        with open(log_path, 'r') as f:
            return f.readlines()
    else:
        # Modo Simulación
        print("\nUsando el modo SIMULACIÓN: Enviando logs de la lista predefinida.")
        return LOG_LINES

def send_logs_to_siem(logger, log_source):
    """Envía cada línea de la fuente de logs al SIEM."""
    
    source_type = "Simulación" if isinstance(log_source, list) else "Archivo"
    print(f"Iniciando el envío de logs ({source_type}) a: {SIEM_HOST}:{SIEM_PORT} por {PROTOCOL}...")

    for i, line in enumerate(log_source):
        line_stripped = line.strip()
        if line_stripped: # Asegura no enviar líneas vacías
            logger.info(line_stripped) 
            print(f"Enviado log {i+1} ({PROTOCOL}): {line_stripped[:80]}...")
        
        # Pausa para simular tráfico (solo en modo simulación o si no es un archivo muy grande)
        if source_type == "Simulación":
            time.sleep(0.5) 

    print("\nEnvío completado.")
    print("Verifica el host SIEM/colector.")


if __name__ == "__main__":
    try:
        # 1. Configurar el canal de Syslog
        siem_logger = setup_syslog_handler(PROTOCOL)
        
        # 2. Obtener la fuente de logs (lista o contenido del archivo)
        logs_to_send = get_logs_to_send(LOG_FILE_PATH)
        
        # 3. Enviar los logs
        send_logs_to_siem(siem_logger, logs_to_send)
        
    except FileNotFoundError as fnfe:
        print(f"\n--- ERROR ---")
        print(fnfe)
        print("---")
    except ConnectionRefusedError:
        print("\n--- ERROR ---")
        print(f"Conexión rechazada. Asegúrate de que el SIEM/colector esté escuchando en {PROTOCOL} en {SIEM_HOST}:{SIEM_PORT}")
        print("---")
    except Exception as e:
        print(f"\nOcurrió un error inesperado: {e}")