#!/usr/bin/env python3
"""
ICMP César Decoder - Lee captura filtrando por IP de destino hardcodeada
Uso: python3 03.py <archivo.pcapng>
"""

import sys
import re
from scapy.all import rdpcap, ICMP, IP

# ============ CONFIGURACIÓN ============
# IP de destino (la máquina que recibió los paquetes originales)
TARGET_IP = "192.168.3.246"  # <--- CAMBIA ESTA IP POR LA QUE USASTE COMO DESTINO
# ======================================

# Colores ANSI para terminal
GREEN = "\033[92m"
RESET = "\033[0m"

# Diccionario de palabras en español
SPANISH_WORDS = {
    "el",
    "la",
    "los",
    "las",
    "un",
    "una",
    "unos",
    "unas",
    "y",
    "e",
    "o",
    "u",
    "que",
    "de",
    "en",
    "por",
    "para",
    "con",
    "sin",
    "sobre",
    "tras",
    "durante",
    "entre",
    "hasta",
    "desde",
    "hola",
    "mundo",
    "mensaje",
    "codigo",
    "cifrado",
    "cesar",
    "prueba",
    "test",
    "python",
    "scapy",
    "wireshark",
    "este",
    "esta",
    "esto",
    "estos",
    "estas",
    "tiene",
    "puede",
    "debe",
    "hacer",
    "decir",
    "tener",
    "tiempo",
    "persona",
    "año",
    "dia",
    "cosa",
    "hombre",
    "mujer",
    "vida",
    "mundo",
    "trabajo",
    "casa",
    "familia",
    "amigo",
    "amiga",
    "bueno",
    "buena",
    "malo",
    "mala",
    "grande",
    "pequeño",
    "nuevo",
    "viejo",
    "joven",
    "vieja",
    "es",
    "son",
    "estoy",
    "estas",
    "estamos",
    "estan",
    "hola",
    "como",
    "estas",
    "bien",
    "gracias",
    "adios",
    "amor",
    "paz",
    "luz",
    "vida",
    "alma",
    "corazon",
    "que",
    "tal",
    "todo",
    "bien",
    "muy",
    "mas",
    "menos",
    "si",
    "no",
    "ya",
    "asi",
    "aqui",
    "alli",
}


def extract_message_from_icmp(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error al leer el archivo: {e}")
        sys.exit(1)

    characters = []
    packet_count = 0
    skipped_count = 0

    for pkt in packets:
        if IP in pkt and ICMP in pkt:
            ip_layer = pkt[IP]
            icmp_layer = pkt[ICMP]

            # Solo procesar paquetes con destino = TARGET_IP
            if ip_layer.dst != TARGET_IP:
                skipped_count += 1
                continue

            # Obtener el payload del ICMP
            if hasattr(icmp_layer, "payload") and icmp_layer.payload:
                payload = bytes(icmp_layer.payload)

                if len(payload) > 0:
                    char_byte = payload[0]

                    # Ignorar byte 0x00 (paquete de terminación)
                    if char_byte != 0x00:
                        characters.append(char_byte)
                        packet_count += 1

                        # Mostrar caracter si es imprimible
                        if 32 <= char_byte <= 126:
                            char_display = chr(char_byte)
                        else:
                            char_display = "?"

    if packet_count == 0:
        ips = set()
        for pkt in packets:
            if IP in pkt:
                ips.add(pkt[IP].dst)
        for ip in sorted(ips):
            print(f"    - {ip}")
        return ""

    # Convertir a string
    message = ""
    for b in characters:
        if 32 <= b <= 126:
            message += chr(b)
        else:
            message += "?"

    return message


def rot_decrypt(text, shift):
    """Aplica ROT (César) con desplazamiento shift"""
    result = []

    for char in text:
        if "A" <= char <= "Z":
            shifted = ord(char) - shift
            if shifted < ord("A"):
                shifted += 26
            result.append(chr(shifted))
        elif "a" <= char <= "z":
            shifted = ord(char) - shift
            if shifted < ord("a"):
                shifted += 26
            result.append(chr(shifted))
        else:
            result.append(char)

    return "".join(result)


def score_text(text):
    """Calcula una puntuación para un texto basado en palabras en español"""
    words = re.findall(r"\b[a-zA-Záéíóúüñ]+\b", text.lower())

    if not words:
        return 0

    score = 0
    for word in words:
        if word in SPANISH_WORDS:
            score += 1
        if len(word) > 5 and word in SPANISH_WORDS:
            score += 2

    if text and text[0].isupper():
        score += 2

    proportion = score / len(words) if words else 0
    score += proportion * 5

    return score


def decrypt_cesar(message):
    """Prueba todos los desplazamientos y muestra resultados numerados con el mejor en verde"""
    if not message or all(c == "?" for c in message):
        print("[!] El mensaje extraído no contiene caracteres válidos")
        return

    results = []

    # Probar los 25 desplazamientos (1-25)
    for shift in range(1, 26):
        decrypted = rot_decrypt(message, shift)
        score = score_text(decrypted)
        results.append({"shift": shift, "text": decrypted, "score": score})

    # Encontrar el mejor resultado
    best = max(results, key=lambda x: x["score"])

    # Mostrar todas las combinaciones numeradas
    print("\n[+] Todas las combinaciones posibles:\n")

    for i, result in enumerate(results):
        # Si es la mejor opción, mostrarla en verde
        if result["shift"] == best["shift"]:
            print(f"{GREEN}{i:2d}  ROT{result['shift']:2d}: {result['text']}{RESET}")
        else:
            print(f"{i:2d}  ROT{result['shift']:2d}: {result['text']}")

    # Mostrar resumen final
    ("\n" + "=" * 70)
    print(f"{GREEN}📌 OPCIÓN MÁS PROBABLE (marcada en verde){RESET}")
    print("=" * 70)
    print(f"{GREEN}Desplazamiento: ROT{best['shift']}{RESET}")
    print(f"{GREEN}Mensaje: {best['text']}{RESET}")
    print("=" * 70)


def main():
    if len(sys.argv) != 2:
        sys.exit(1)

    pcap_file = sys.argv[1]

    import os

    if not os.path.exists(pcap_file):
        print(f"[!] Error: El archivo '{pcap_file}' no existe")
        sys.exit(1)

    # Extraer mensaje
    message = extract_message_from_icmp(pcap_file)

    if not message:
        print("\n[!] No se encontraron caracteres en la captura")
        print("[!] Consejos:")
        print(f"    1. Verifica que TARGET_IP sea correcta (actual: {TARGET_IP})")
        print("    2. Verifica que la captura contenga paquetes ICMP")
        print("    3. Verifica que los paquetes tengan payload")
        sys.exit(1)

    # Descifrar
    decrypt_cesar(message)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario")
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        import traceback

        traceback.print_exc()
