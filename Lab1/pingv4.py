from scapy.all import *
import sys
import time
import struct
import datetime

def crear_paquete_icmp(caracter, seq_number, timestamp):
    # Crear paquete IP
    ip = IP(dst="104.22.63.197", src="192.168.88.24")

    # Crear paquete ICMP con tipo 8 (Echo Request) y código 0
    icmp = ICMP(type=8, code=0)
    icmp.id = 0x0300
    icmp.seq = seq_number

    # Convertir timestamp a formato Little Endian
    ts_le = struct.pack('<I', int(timestamp.timestamp()))

    # Crear el payload del paquete ICMP, incluyendo el timestamp
    payload_fijo = bytes.fromhex("f681050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
    
    # Agregar el caracter del mensaje al inicio del payload
    data = ts_le + b'\x00\x00\x00\x00' + bytes(caracter, 'utf-8') + payload_fijo[1:]

    # Crear el paquete completo
    paquete = ip / icmp / Raw(load=data)

    return paquete

def enviar_paquetes_icmp(mensaje):
    # Obtener la hora actual
    timestamp_actual = datetime.datetime.now()

    # Dividir el mensaje en caracteres individuales
    caracteres = list(mensaje)

    for i, caracter in enumerate(caracteres):
        # Crear paquete ICMP con un carácter en el payload
        paquete = crear_paquete_icmp(caracter, seq_number=i + 1, timestamp=timestamp_actual)
        
        # Enviar el paquete
        send(paquete, verbose=0)
        
        print(f"Sent 1 packet with character '{caracter}'.")
        # Esperar un poco para no saturar la red
        time.sleep(0.1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py \"texto a enviar\"")
        sys.exit(1)
    
    mensaje = sys.argv[1]
    enviar_paquetes_icmp(mensaje)

