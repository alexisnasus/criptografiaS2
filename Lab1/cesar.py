import sys

def cesar_cipher(text, shift):
    result = ""

    # Recorremos cada carácter del texto
    for char in text:
        if char.isalpha():  # Verificamos si el carácter es una letra
            shift_base = ord('A') if char.isupper() else ord('a')
            # Calculamos el nuevo carácter cifrado
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            # Si no es una letra, no lo cambiamos
            result += char

    return result

if __name__ == "__main__":
    # Verificamos que se pasen los parámetros correctos
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"<texto>\" <corrimiento>")
        sys.exit(1)

    # Obtenemos el texto y el desplazamiento desde los argumentos
    input_text = sys.argv[1]
    try:
        shift = int(sys.argv[2])
    except ValueError:
        print("El corrimiento debe ser un número entero.")
        sys.exit(1)

    # Llamamos a la función de cifrado y mostramos el resultado
    encrypted_text = cesar_cipher(input_text, shift)
    print(f"{encrypted_text}")

