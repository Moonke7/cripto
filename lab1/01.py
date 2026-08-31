import sys


def cifrado_cesar(texto, n):
    resultado = ""

    for caracter in texto:
        if caracter.isalpha():
            base = ord("A") if caracter.isupper() else ord("a")
            resultado += chr((ord(caracter) - base + n) % 26 + base)
        else:
            resultado += caracter

    return resultado


texto = sys.argv[1]
n = int(sys.argv[2])

print(cifrado_cesar(texto, n))
