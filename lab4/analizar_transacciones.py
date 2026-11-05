from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.utils import PcapReader


RSA_LABEL = b"RSA_PIN|"
AES_LABEL = b"AESGCM|"
SALT_LENGTH = 16
NONCE_LENGTH = 12
AES_KEY_LENGTH = 32
BASE_DIR = Path(__file__).resolve().parent
PCAP_PATH = BASE_DIR / "transacciones_cifradas.pcap"
PRIVATE_KEY_PATH = BASE_DIR / "clave_privada.pem"


def read_application_records(
    pcap_path: Path,
) -> tuple[list[tuple[int, bytes]], list[tuple[int, bytes]]]:
    # Recopila los registros de aplicación de los paquetes TCP de la captura.
    rsa_records: list[tuple[int, bytes]] = []
    aes_records: list[tuple[int, bytes]] = []

    with PcapReader(str(pcap_path)) as capture:
        for frame_number, packet in enumerate(capture, start=1):
            if TCP not in packet or Raw not in packet:
                continue

            payload = bytes(packet[Raw].load)
            if payload.startswith(RSA_LABEL):
                rsa_records.append((frame_number, payload))
            elif payload.startswith(AES_LABEL):
                aes_records.append((frame_number, payload))

    return rsa_records, aes_records


def recover_pin_and_key(
    payload: bytes, private_key_path: Path
) -> tuple[bytes, bytes, bytes]:
    # Descifra el PIN con RSA-OAEP y deriva la clave AES de 256 bits con Scrypt.
    salt_start = len(RSA_LABEL)
    salt_end = salt_start + SALT_LENGTH
    salt = payload[salt_start:salt_end]
    encrypted_pin = payload[salt_end:]
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    pin = private_key.decrypt(
        encrypted_pin,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    kdf = Scrypt(
        salt=salt,
        length=AES_KEY_LENGTH,
        n=2**14,
        r=8,
        p=1,
    )
    aes_key = kdf.derive(pin)
    return pin, salt, aes_key


def decrypt_transactions(
    records: list[tuple[int, bytes]], aes_key: bytes
) -> list[tuple[int, str]]:
    # Descifra los registros, verifica sus etiquetas AES-GCM y conserva los mensajes originales.
    aes = AESGCM(aes_key)
    transactions: list[tuple[int, str]] = []

    for frame, payload in records:
        nonce_start = len(AES_LABEL)
        ciphertext_start = nonce_start + NONCE_LENGTH
        nonce = payload[nonce_start:ciphertext_start]
        ciphertext_and_tag = payload[ciphertext_start:]
        # AESGCM.decrypt verifica la etiqueta de autenticación antes de devolver el texto plano.
        plaintext = aes.decrypt(nonce, ciphertext_and_tag, associated_data=None)
        original = plaintext.decode("utf-8")
        transactions.append((frame, original))

    return transactions


def main() -> int:
    try:
        rsa_records, aes_records = read_application_records(PCAP_PATH)
        rsa_frame, rsa_payload = rsa_records[0]
        pin, salt, aes_key = recover_pin_and_key(rsa_payload, PRIVATE_KEY_PATH)
        transactions = decrypt_transactions(aes_records, aes_key)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # No se imprime la clave AES derivada; solo se necesita para descifrar.
    print(f"PCAP: {PCAP_PATH}")
    print(f"Paquete RSA_PIN: {rsa_frame}")
    print(f"Salt ({len(salt)} bytes): {salt.hex()}")
    print(f"PIN recuperado (RSA-OAEP/SHA-256): {pin.decode('ascii')}")
    print("Scrypt: n=16384, r=8, p=1, dklen=32 bytes")
    print(f"Transacciones AES-GCM autenticadas: {len(transactions)}/{len(aes_records)}")
    print()
    print("Mensajes originales recuperados:")
    for frame, original in transactions:
        print(f"Paquete {frame}: {original}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
