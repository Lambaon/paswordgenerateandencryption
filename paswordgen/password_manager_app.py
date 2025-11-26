import tkinter as tk
from tkinter import simpledialog, messagebox
import time
import threading
from cryptography.fernet import InvalidToken
import clipboard

from security_manager import SecurityManager
from password_generator import generate_strong_password


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Менеджер Паролів")
        self.security_manager: SecurityManager = None
        self.inactivity_timeout = 300
        self.last_activity = time.time()
        self.clipboard_clear_timer = None

        self.root.withdraw()
        self.show_login_screen()
        self.check_inactivity()

    def check_inactivity(self):
        if self.security_manager and (time.time() - self.last_activity) > self.inactivity_timeout:
            self.lock_app()
            messagebox.showinfo("Блокування", "Додаток автоматично заблоковано через неактивність.")

        self.root.after(1000, self.check_inactivity)

    def record_activity(self, event=None):
        self.last_activity = time.time()

    def lock_app(self):
        if self.security_manager:
            messagebox.showinfo("Блокування", "Доступ заблоковано.")
            self.security_manager = None

            for widget in self.root.winfo_children():
                widget.destroy()

            self.show_login_screen()

    def attempt_unlock(self):
        master_pass = self.master_pass_entry.get()
        if not master_pass:
            messagebox.showerror("Помилка", "Введіть пароль.")
            return

        try:
            manager = SecurityManager(master_pass)
            test_encrypted = manager.encrypt_password("test_phrase")
            manager.decrypt_password(test_encrypted)

            self.security_manager = manager
            self.login_window.destroy()
            self.root.deiconify()
            self.root.bind_all('<Key>', self.record_activity)
            self.root.bind_all('<Motion>', self.record_activity)
            self.setup_main_ui()

        except InvalidToken:
            messagebox.showerror("Помилка", "Невірний майстер-пароль. Спробуйте ще раз.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Виникла помилка: {e}")

    def show_login_screen(self):
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Вхід до Менеджера")
        self.login_window.geometry("300x150")

        tk.Label(self.login_window, text="Майстер-пароль:").pack(pady=10)
        self.master_pass_entry = tk.Entry(self.login_window, show="*", width=30)
        self.master_pass_entry.pack(pady=5, padx=10)

        tk.Button(self.login_window, text="Розблокувати", command=self.attempt_unlock).pack(pady=10)

        self.login_window.protocol("WM_DELETE_WINDOW", self.root.quit)
        self.login_window.grab_set()

    def setup_main_ui(self):
        self.root.geometry("400x350")

        tk.Label(self.root, text="Менеджер Паролів (Розблоковано)", font=("Arial", 14)).pack(pady=20)

        tk.Button(self.root, text="Згенерувати Пароль", command=self.show_password_generator).pack(pady=10, fill=tk.X,
                                                                                                   padx=50)

        tk.Button(self.root, text="Шифрування / Розшифрування Повідомлень ✉️",
                  command=self.handle_crypto_operation).pack(pady=10, fill=tk.X, padx=50)

        tk.Button(self.root, text="Заблокувати Додаток", command=self.lock_app).pack(pady=20, fill=tk.X, padx=50)

    def copy_to_clipboard_securely(self, text):
        try:
            clipboard.copy(text)
            messagebox.showinfo("Копіювання", "Текст скопійовано. Буфер буде очищено через 30 секунд.")

            if self.clipboard_clear_timer:
                self.root.after_cancel(self.clipboard_clear_timer)

            self.clipboard_clear_timer = self.root.after(30000, self.clear_clipboard)

        except Exception:
            messagebox.showerror("Помилка", "Неможливо скопіювати до буфера обміну.")

    def clear_clipboard(self):
        try:
            clipboard.copy("")
            messagebox.showinfo("Безпека", "Буфер обміну очищено.")
            self.clipboard_clear_timer = None
        except Exception:
            pass

    def show_password_generator(self):
        new_pass = generate_strong_password(length=18)

        if messagebox.askyesno("Новий Пароль", f"Згенеровано: {new_pass}\n\nСкопіювати в буфер обміну?"):
            self.copy_to_clipboard_securely(new_pass)

    def handle_crypto_operation(self):
        if not self.security_manager:
            messagebox.showerror("Помилка", "Додаток не розблоковано.")
            return

        action = simpledialog.askstring("Криптографічна Операція",
                                        "Введіть 'ш' (шифрування) або 'р' (розшифрування):",
                                        parent=self.root)

        if action and action.lower() == 'ш':
            self._handle_encryption()
        elif action and action.lower() == 'р':
            self._handle_decryption()
        else:
            messagebox.showinfo("Скасовано", "Операцію скасовано.")

    def _handle_encryption(self):
        original = simpledialog.askstring("Шифрування Повідомлення", "Введіть текст для шифрування:")
        if original:
            try:
                encrypted_bytes = self.security_manager.encrypt_password(original)
                encrypted_str = encrypted_bytes.decode()

                self._show_encrypted_message(encrypted_str)

            except Exception as e:
                messagebox.showerror("Помилка Криптографії", f"Неможливо виконати операцію: {e}")

    def _handle_decryption(self):
        encrypted_str = simpledialog.askstring("Розшифрування Повідомлення", "Вставте зашифрований текст:")
        if encrypted_str:
            try:
                encrypted_bytes = encrypted_str.encode()
                decrypted = self.security_manager.decrypt_password(encrypted_bytes)
                messagebox.showinfo("Розшифровано Успішно", f"Розшифроване повідомлення:\n\n{decrypted}")
            except InvalidToken:
                messagebox.showerror("Помилка", "Невірний ключ (майстер-пароль). Неможливо розшифрувати текст.")
            except Exception as e:
                messagebox.showerror("Помилка", f"Неможливо розшифрувати. Переконайтеся, що текст коректний: {e}")

    def _show_encrypted_message(self, encrypted_text):
        msg_window = tk.Toplevel(self.root)
        msg_window.title("Зашифроване Повідомлення")
        msg_window.geometry("500x200")

        tk.Label(msg_window, text="Зашифрований текст (Base64). Надішліть це другу:", wraplength=480).pack(pady=5)

        text_widget = tk.Text(msg_window, height=5, width=60)
        text_widget.insert(tk.END, encrypted_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(pady=5, padx=10)

        tk.Button(msg_window,
                  text="Копіювати Зашифрований Текст 📋",
                  command=lambda: self.copy_to_clipboard_securely(encrypted_text)
                  ).pack(pady=10)

        msg_window.grab_set()


if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
