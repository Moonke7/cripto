import sys
import time
from scapy.all import IP, ICMP, send

# ============ CONFIGURACIÓN ============
TARGET_IP = "192.168.1.1"  # Loopback
DELAY = 1.0  # 1 segundo
# ======================================


def send_icmp_char(message):
    print(f"[*] Enviando mensaje: '{message}' a {TARGET_IP}")

    icmp_id = 1234  # ID constante para simular una misma sesión

    # Construcción de los bloques de padding según la rúbrica
    # 3 bytes "coherentes" (simulando parte del timestamp)
    tres_bytes = bytes([0x08, 0x09, 0x0A])
    # 5 bytes en 0x00
    cinco_ceros = b"\x00" * 5
    # Rango hexadecimal desde 0x10 hasta 0x37
    padding_hex = bytes(range(0x10, 0x38))

    for i, char in enumerate(message):
        # Ensamblamos: Carácter (1 byte) + 3 bytes + 5x00 + rango hex
        data = char.encode("utf-8") + tres_bytes + cinco_ceros + padding_hex

        # Seq se incrementa en cada iteración (i+1)
        packet = IP(dst=TARGET_IP) / ICMP(id=icmp_id, seq=i + 1) / data
        send(packet, verbose=False)
        print("Enviando: ", packet)
        time.sleep(DELAY)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 icmp_sender.py <mensaje>")
        sys.exit(1)

    send_icmp_char(sys.argv[1])
