import tkinter as tk
from tkinter import messagebox
from password_manager import (
    derive_key,
    load_or_create_salt,
    load_vault,
    save_vault,
    add_entry
)

AUTO_CLEAR_SECONDS = 15

class PasswordManagerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("450x380")
        self.root.resizable(False, False)

        self.key = None
        self.vault = None

        self.login_screen()

    # ---------------- Utility ----------------
    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # ---------------- Login Screen ----------------
    def login_screen(self):
        self.clear()
        tk.Label(self.root, text="🔐 Password Manager", font=("Arial", 16, "bold")).pack(pady=25)

        tk.Label(self.root, text="Master Password").pack()
        self.master_entry = tk.Entry(self.root, show="*", width=30)
        self.master_entry.pack(pady=10)

        tk.Button(self.root, text="Unlock Vault", command=self.unlock).pack(pady=15)

    def unlock(self):
        master_password = self.master_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Enter master password")
            return

        try:
            salt = load_or_create_salt()
            self.key = derive_key(master_password, salt)
            self.vault = load_vault(self.key)
            self.vault_screen()
        except Exception:
            messagebox.showerror("Error", "Invalid master password")

    # ---------------- Vault Screen ----------------
    def vault_screen(self):
        self.clear()
        tk.Label(self.root, text="🔑 Vault", font=("Arial", 16, "bold")).pack(pady=10)

        self.listbox = tk.Listbox(self.root, width=55)
        self.listbox.pack(pady=10)
        self.refresh_list()

        tk.Button(self.root, text="View Password", command=self.view_password).pack(pady=3)
        tk.Button(self.root, text="Copy Password", command=self.copy_password).pack(pady=3)
        tk.Button(self.root, text="Add Password", command=self.add_screen).pack(pady=3)
        tk.Button(self.root, text="Logout", command=self.login_screen).pack(pady=3)

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for entry in self.vault["entries"]:
            self.listbox.insert(tk.END, f"{entry['site']} | {entry['username']}")

    # ---------------- View Password ----------------
    def view_password(self):
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Select an entry first")
            return

        entry = self.vault["entries"][selected[0]]

        messagebox.showinfo(
            "Stored Password",
            f"Site: {entry['site']}\n"
            f"Username: {entry['username']}\n"
            f"Password: {entry['password']}"
        )

    # ---------------- Copy + Auto Clear ----------------
    def copy_password(self):
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Select an entry first")
            return

        password = self.vault["entries"][selected[0]]["password"]

        self.root.clipboard_clear()
        self.root.clipboard_append(password)

        messagebox.showinfo(
            "Copied",
            f"Password copied to clipboard.\n"
        )

        self.root.after(AUTO_CLEAR_SECONDS * 1000, self.clear_clipboard)

    def clear_clipboard(self):
        self.root.clipboard_clear()

    # ---------------- Add Password ----------------
    def add_screen(self):
        add_win = tk.Toplevel(self.root)
        add_win.title("Add Password")
        add_win.geometry("360x300")
        add_win.resizable(False, False)

        tk.Label(add_win, text="Website").pack(pady=5)
        site = tk.Entry(add_win, width=30)
        site.pack()

        tk.Label(add_win, text="Username").pack(pady=5)
        user = tk.Entry(add_win, width=30)
        user.pack()

        tk.Label(add_win, text="Password").pack(pady=5)
        pwd = tk.Entry(add_win, show="*", width=30)
        pwd.pack()

        # ---- Show / Hide Toggle ----
        show_var = tk.BooleanVar()

        def toggle_password():
            pwd.config(show="" if show_var.get() else "*")

        tk.Checkbutton(
            add_win,
            text="Show Password",
            variable=show_var,
            command=toggle_password
        ).pack(pady=5)

        def save():
            if not site.get() or not user.get() or not pwd.get():
                messagebox.showerror("Error", "All fields required")
                return

            add_entry(self.vault, site.get(), user.get(), pwd.get())
            save_vault(self.vault, self.key)
            self.refresh_list()
            add_win.destroy()

        tk.Button(add_win, text="Save", command=save).pack(pady=15)

# ---------------- Run Application ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerUI(root)
    root.mainloop()
