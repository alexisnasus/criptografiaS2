from scapy.all import rdpcap, ICMP, Raw
from spellchecker import SpellChecker
from colorama import Fore, Style

def cesar_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            # Calcular la posición en el alfabeto (solo minúsculas)
            decrypted_char = chr((ord(char) - 97 - shift) % 26 + 97)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text

def es_mensaje_probable(texto):
    spell = SpellChecker(language='es')
    palabras = texto.split()
    # Contar palabras válidas en español
    palabras_validas = [palabra for palabra in palabras if palabra in spell]
    return len(palabras_validas)

def descifrar_todos(texto_cifrado):
    probable_message = ""
    max_valid_words = 0
    probable_shift = 0

    for shift in range(26):
        texto_descifrado = cesar_decrypt(texto_cifrado, shift)
        num_palabras_validas = es_mensaje_probable(texto_descifrado)
        
        print(f"Desplazamiento {shift}: {texto_descifrado}")
        
        if num_palabras_validas > max_valid_words:
            max_valid_words = num_palabras_validas
            probable_message = texto_descifrado
            probable_shift = shift

    print(f"\n{Fore.GREEN}Mensaje más probable con desplazamiento {probable_shift}: {probable_message}{Style.RESET_ALL}")

def extraer_datos_pcapng(nombre_archivo):
    paquetes = rdpcap(nombre_archivo)
    mensaje_cifrado = ""
    
    for paquete in paquetes:
        if ICMP in paquete and paquete[ICMP].type == 8:
            # Obtener la carga útil (payload) del paquete ICMP
            carga_util = bytes(paquete[Raw].load)
            
            # Extraer solo el carácter (omitir los primeros 8 bytes de timestamp y padding)
            caracter_cifrado = carga_util[8:9].decode('utf-8', errors='ignore')
            mensaje_cifrado += caracter_cifrado
    
    return mensaje_cifrado

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: python3 programa.py archivo.pcapng")
        sys.exit(1)
    
    nombre_archivo = sys.argv[1]
    texto_cifrado = extraer_datos_pcapng(nombre_archivo)
    
    print(f"Texto cifrado extraído: {texto_cifrado}")
    descifrar_todos(texto_cifrado)

