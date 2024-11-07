from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
import binascii
from Crypto.Util.Padding import pad, unpad

TAMAÑO_CLAVE = {'DES': 8, '3DES': 24, 'AES-256': 32}
TAMAÑO_IV = {'DES': 8, '3DES': 8, 'AES-256': 16}
TAMAÑO_BLOQUE = {'DES': 8, '3DES': 8, 'AES-256': 16}

def solicitar_datos():
    clave = input("Ingrese la clave: ").strip().encode()
    iv = input("Ingrese el IV: ").strip().encode()
    texto = input("Ingrese el texto a cifrar: ").strip().encode()
    return clave, iv, texto

def ajustar_clave(clave, tamaño, algoritmo):
    if len(clave) < tamaño:
        clave += get_random_bytes(tamaño - len(clave))
    elif len(clave) > tamaño:
        clave = clave[:tamaño]
    
    if algoritmo == '3DES':
        try:
            clave = DES3.adjust_key_parity(clave)
        except ValueError as e:
            raise ValueError("Triple DES key degenerates to single DES")
    return clave

def ajustar_iv(iv, tamaño):
    if len(iv) < tamaño:
        iv += get_random_bytes(tamaño - len(iv))
    elif len(iv) > tamaño:
        iv = iv[:tamaño]
    return iv

def cifrar_descifrar(algoritmo, clave, iv, texto):
    try:
        tamaño_clave = TAMAÑO_CLAVE[algoritmo]
        tamaño_iv = TAMAÑO_IV[algoritmo]
        tamaño_bloque = TAMAÑO_BLOQUE[algoritmo]

        clave = ajustar_clave(clave, tamaño_clave, algoritmo)
        iv = ajustar_iv(iv, tamaño_iv)
        print(f"Clave ajustada ({algoritmo}): {binascii.hexlify(clave).decode()}")
        print(f"IV ajustado ({algoritmo}): {binascii.hexlify(iv).decode()}")

        if algoritmo == 'DES':
            cipher = DES.new(clave, DES.MODE_CBC, iv)
        elif algoritmo == '3DES':
            cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        elif algoritmo == 'AES-256':
            cipher = AES.new(clave, AES.MODE_CBC, iv)
        else:
            raise ValueError("Algoritmo no soportado")

        texto_padded = pad(texto, tamaño_bloque)
        texto_cifrado = cipher.encrypt(texto_padded)
        print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")

        if algoritmo == 'DES':
            decipher = DES.new(clave, DES.MODE_CBC, iv)
        elif algoritmo == '3DES':
            decipher = DES3.new(clave, DES3.MODE_CBC, iv)
        elif algoritmo == 'AES-256':
            decipher = AES.new(clave, AES.MODE_CBC, iv)

        texto_descifrado_padded = decipher.decrypt(texto_cifrado)
        texto_descifrado = unpad(texto_descifrado_padded, tamaño_bloque)
        print(f"Texto descifrado: {texto_descifrado.decode()}")

    except ValueError as e:
        print(f"No se pudo realizar el cifrado y descifrado con {algoritmo}: {e}")

def main():
    clave, iv, texto = solicitar_datos()
    for algoritmo in ['DES', '3DES', 'AES-256']:
        print(f"\n---- Cifrado y Descifrado usando {algoritmo} ----")
        cifrar_descifrar(algoritmo, clave, iv, texto)

if __name__ == "__main__":
    main()
