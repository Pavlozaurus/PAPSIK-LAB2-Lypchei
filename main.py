import os
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# Константи
SAVE_PATH = "C:\\Python"  # Директорія для збереження зашифрованих файлів
BLOCK_SIZE = AES.block_size  # Розмір блоку AES (16 байт)
KEY_SIZE = 32  # Довжина ключа (256 біт = 32 байти)

# Функція доповнення до даних, щоб їх довжина стала кратною BLOCK_SIZE
def pad(data):
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length] * padding_length)

# Функція видалення доповнення
def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# Графічне вікно для введення секретного ключа з перевіркою довжини
def secure_input_key_gui(prompt, expected_length):

    def on_submit():
        user_input = entry.get()
        if len(user_input) == expected_length:
            root.user_input = user_input
            root.destroy()
        else:
            error_label.config(
                text=f"Ключ має складатися рівно з {expected_length} символів!", fg="red"
            )

    root = tk.Tk()
    root.title("Введення секретного ключа")
    root.geometry("400x200")
    root.resizable(False, False)

    tk.Label(root, text=prompt).pack(pady=10)

    entry = tk.Entry(root, show="*", width=50)  # Поле введення з маскуванням
    entry.pack(pady=5)
    entry.focus()

    error_label = tk.Label(root, text="", fg="red")
    error_label.pack()

    submit_button = tk.Button(root, text="ОК", command=on_submit)
    submit_button.pack(pady=10)

    root.user_input = None
    root.mainloop()

    return root.user_input.encode() if root.user_input else None

# Функція зашифрування тексту у файл
def encrypt_text_to_file(text, key, file_name):
    """
    Шифрує текст та записує його у файл разом із IV та HMAC.
    """
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    hmac = HMAC.new(key, digestmod=SHA256)

    encrypted_data = cipher.encrypt(pad(text.encode()))
    hmac.update(encrypted_data)

    file_path = os.path.join(SAVE_PATH, file_name)
    with open(file_path, "wb") as file:
        file.write(iv + encrypted_data + hmac.digest())
    return file_path

# Функція розшифрування файлу у відкритиий текст
def decrypt_file_to_text(file_name, key):
    file_path = os.path.join(SAVE_PATH, file_name)
    with open(file_path, "rb") as file:
        data = file.read()
        iv, encrypted_data, file_hmac = data[:BLOCK_SIZE], data[BLOCK_SIZE:-32], data[-32:]

    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(encrypted_data)
    hmac.verify(file_hmac)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data))
    return decrypted_data.decode()

# Функція видалення всіх зашифрованих файлів
def clear_encrypted_files():
    """
    Видаляє всі файли з розширенням '.bin' у директорії SAVE_PATH.
    """
    for file in os.listdir(SAVE_PATH):
        if file.endswith('.bin'):
            os.remove(os.path.join(SAVE_PATH, file))
    print("Усі зашифровані файли було видалено!")

# Функція видалення конкретного файлу
def delete_specific_file(file_name):
    file_path = os.path.join(SAVE_PATH, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Файл {file_name} успішно видалено!")
    else:
        print("Даний файл не знайдено..")

# Головний блок програми
if __name__ == "__main__":
    os.makedirs(SAVE_PATH, exist_ok=True)  # Створює директорію SAVE_PATH, якщо її немає

    print("Що ви бажаєте зробити?")
    print("0 - Зашифрувати текст")
    print("1 - Розшифрувати файл")
    print("2 - Видалити файли")
    choice = input("Ваш вибір: ")

    if choice == "0":
        text = input("Введіть текст для подальшого шифрування: ")
        key = secure_input_key_gui("Задайте секретний ключ для шифрування тексту рівно з 32 символів:", 32)
        if not key:
            print("Ввід скасовано!") # Скасовує введення ключу при натисканні кнопки "Х"
            exit()
        file_name = input("Введіть назву для збереження файлу (з розширенням .bin): ")
        if not file_name.endswith(".bin"):
            print("Помилка: Назва файлу має обов'язково закінчуватися на '.bin'.")
        else:
            file_path = encrypt_text_to_file(text, key, file_name)
            print(f"Текст успішно зашифровано та збережено у файл {file_path}")

    elif choice == "1":
        files = [f for f in os.listdir(SAVE_PATH) if f.endswith('.bin')]
        if not files:
            print("Немає доступних файлів для розшифрування..")
        else:
            print("Доступні файли для розшифрування:")
            for f in files:
                print(f"- {f}")
            file_name = input("Введіть назву файлу для розшифрування (з розширенням .bin): ")
            if file_name in files:
                key = secure_input_key_gui("Введіть секретний ключ для розшифрування файлу (32 символи):", 32)
                if not key:
                    print("Ввід скасовано!")
                    exit()
                try:
                    text = decrypt_file_to_text(file_name, key)
                    print("Розшифрований текст:")
                    print(text)
                except ValueError:
                    print("Помилка розшифрування: Було введено неправильний ключ!")
            else:
                print("Вибачте, такий файл не знайдено.")

    elif choice == "2":
        print("Оберіть дію:")
        print("0 - Видалити всі файли")
        print("1 - Видалити конкретний файл")
        sub_choice = input("Ваш вибір: ")

        if sub_choice == "0":
            clear_encrypted_files()
        elif sub_choice == "1":
            file_name = input("Введіть назву файлу для видалення (з розширенням .bin): ")
            delete_specific_file(file_name)
        else:
            print("Будь ласка, ретельно перевіряйте дані, які ви вводите!")
    else:
        print("Будь ласка, обирайте лише із запропонованих варіантів!")