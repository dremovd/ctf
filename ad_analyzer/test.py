import requests

url = "http://localhost:8000/analyze"  # Asegúrate de que la URL sea correcta
file_path = "test.txt"  # Cambia esto por la ruta de tu archivo

with open(file_path, "r") as f:
    files = {"file": (file_path, f)}
    response = requests.post(url, files=files)

print(response.status_code)
print(response.content.decode())
