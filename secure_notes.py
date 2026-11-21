import os
import base64
import hashlib
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet, InvalidToken

# Configuration Constants
DATA_DIR = "secure_vault_data"
SALT_FILE = os.path.join(DATA_DIR, "salt.bin")
NOTE_FILE = os.path.join(DATA_DIR, "notes.enc")
AUTO_LOCK_SECONDS = 60  # Locks automatically after 60 seconds of inactivity


class SecureNotesApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Notes with Auto-Lock")
        self.root.geometry("680x500")
        self.root.minsize(560, 420)
        self.root.configure(bg="#1E293B")

        # Application State
        self.fernet: Fernet | None = None
        self.is_unlocked: bool = False
        self.remaining_seconds: int = AUTO_LOCK_SECONDS
        self.timer_job: str | None = None

        # Ensure storage directory exists
        os.makedirs(DATA_DIR, exist_ok=True)

        # Bind activity events to reset the auto-lock countdown
        for event in ("<KeyPress>", "<Motion>", "<ButtonPress>", "<MouseWheel>"):
            self.root.bind_all(event, self.reset_inactivity_timer)

        # Handle window close cleanly
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start on the Lock / Setup Screen
        self.show_lock_screen()

    # ---------------------------------------------------------
    # CRYPTOGRAPHY & FILE STORAGE
    # ---------------------------------------------------------
    def derive_fernet_key(self, password: str, salt: bytes) -> Fernet:
        """Derives a 32-byte URL-safe key using PBKDF2-HMAC-SHA256."""
        raw_key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt,
            iterations=200_000,
            dklen=32,
        )
        encoded_key = base64.urlsafe_b64encode(raw_key)
        return Fernet(encoded_key)

    def is_first_time_setup(self) -> bool:
        """Checks whether a vault has already been initialized."""
        return not (os.path.exists(SALT_FILE) and os.path.exists(NOTE_FILE))

    def encrypt_and_save(self, plaintext: str) -> bool:
        """Encrypts plaintext note content and writes ciphertext to disk."""
        if not self.fernet:
            return False
        try:
            encrypted_bytes = self.fernet.encrypt(plaintext.encode("utf-8"))
            with open(NOTE_FILE, "wb") as f:
                f.write(encrypted_bytes)
            return True
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to save notes:\n{e}")
            return False

    def load_and_decrypt(self) -> str | None:
        """Reads encrypted file from disk and decrypts it using the derived key."""
        if not self.fernet or not os.path.exists(NOTE_FILE):
            return None
        try:
            with open(NOTE_FILE, "rb") as f:
                encrypted_bytes = f.read()
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode("utf-8")
        except InvalidToken:
            return None

    # ---------------------------------------------------------
    # UI SCREENS
    # ---------------------------------------------------------
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_lock_screen(self):
        """Displays either First-Time Password Setup or the Unlock Screen."""
        self.is_unlocked = False
        self.fernet = None
        if self.timer_job:
            self.root.after_cancel(self.timer_job)
            self.timer_job = None

        self.clear_window()
        first_time = self.is_first_time_setup()

        card = tk.Frame(self.root, bg="#0F172A", padx=36, pady=32, bd=1, relief="solid")
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            card,
            text="🔒 SECURE NOTES VAULT",
            font=("Segoe UI", 16, "bold"),
            fg="#38BDF8",
            bg="#0F172A",
        ).pack(pady=(0, 6))

        subtitle = (
            "Create a master password to initialize your encrypted notes."
            if first_time
            else "Enter your master password to decrypt and unlock your notes."
        )
        tk.Label(
            card,
            text=subtitle,
            font=("Segoe UI", 10),
            fg="#94A3B8",
            bg="#0F172A",
            wraplength=340,
        ).pack(pady=(0, 18))

        # Password Entry
        tk.Label(
            card,
            text="Master Password:",
            font=("Segoe UI", 10, "bold"),
            fg="#E2E8F0",
            bg="#0F172A",
            anchor="w",
        ).pack(fill="x")

        self.pass_entry = tk.Entry(
            card,
            show="•",
            font=("Segoe UI", 11),
            bg="#1E293B",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief="flat",
            width=30,
        )
        self.pass_entry.pack(pady=(4, 12), ipady=6)
        self.pass_entry.focus_set()

        # Confirm Password Entry (only on first run)
        self.confirm_entry = None
        if first_time:
            tk.Label(
                card,
                text="Confirm Password:",
                font=("Segoe UI", 10, "bold"),
                fg="#E2E8F0",
                bg="#0F172A",
                anchor="w",
            ).pack(fill="x")

            self.confirm_entry = tk.Entry(
                card,
                show="•",
                font=("Segoe UI", 11),
                bg="#1E293B",
                fg="#F8FAFC",
                insertbackground="#F8FAFC",
                relief="flat",
                width=30,
            )
            self.confirm_entry.pack(pady=(4, 14), ipady=6)

        btn_text = "Create Vault & Unlock" if first_time else "Unlock Notes"
        action_btn = tk.Button(
            card,
            text=btn_text,
            font=("Segoe UI", 10, "bold"),
            bg="#0284C7",
            fg="#FFFFFF",
            activebackground="#0369A1",
            activeforeground="#FFFFFF",
            relief="flat",
            cursor="hand2",
            padx=18,
            pady=8,
            command=self.handle_unlock_or_setup,
        )
        action_btn.pack(fill="x", pady=(6, 0))

        # Allow pressing Enter to submit
        self.root.bind("<Return>", lambda _event: self.handle_unlock_or_setup())

    def handle_unlock_or_setup(self):
        password = self.pass_entry.get()
        if len(password) < 4:
            messagebox.showwarning("Weak Password", "Please enter a password of at least 4 characters.")
            return

        if self.is_first_time_setup():
            confirm = self.confirm_entry.get() if self.confirm_entry else ""
            if password != confirm:
                messagebox.showerror("Mismatch", "Passwords do not match. Please try again.")
                return

            # Generate random 16-byte salt and save initial welcome note
            salt = os.urandom(16)
            with open(SALT_FILE, "wb") as f:
                f.write(salt)

            self.fernet = self.derive_fernet_key(password, salt)
            welcome_text = (
                "Welcome to Secure Notes with Auto-Lock!\n\n"
                "- Your notes are encrypted with Fernet (AES-128-CBC + HMAC) using a PBKDF2 derived key.\n"
                "- After 60 seconds of inactivity, your notes automatically save and lock.\n"
            )
            self.encrypt_and_save(welcome_text)
            self.root.unbind("<Return>")
            self.show_editor_screen(welcome_text)
        else:
            with open(SALT_FILE, "rb") as f:
                salt = f.read()

            self.fernet = self.derive_fernet_key(password, salt)
            decrypted_text = self.load_and_decrypt()

            if decrypted_text is None:
                self.fernet = None
                self.pass_entry.delete(0, tk.END)
                messagebox.showerror("Access Denied", "Incorrect password. Decryption failed.")
                return

            self.root.unbind("<Return>")
            self.show_editor_screen(decrypted_text)

    def show_editor_screen(self, initial_text: str):
        """Displays the decrypted note editor with Save, Lock Now, and Auto-Lock timer."""
        self.clear_window()
        self.is_unlocked = True
        self.remaining_seconds = AUTO_LOCK_SECONDS

        # Top Toolbar
        toolbar = tk.Frame(self.root, bg="#0F172A", padx=14, pady=10)
        toolbar.pack(fill="x")

        tk.Label(
            toolbar,
            text="🔓 Unlocked Note Editor",
            font=("Segoe UI", 12, "bold"),
            fg="#38BDF8",
            bg="#0F172A",
        ).pack(side="left")

        # Lock Now Button
        tk.Button(
            toolbar,
            text="🔒 Lock Now",
            font=("Segoe UI", 9, "bold"),
            bg="#DC2626",
            fg="#FFFFFF",
            activebackground="#B91C1C",
            activeforeground="#FFFFFF",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=5,
            command=self.manual_lock,
        ).pack(side="right", padx=(8, 0))

        # Save Button
        tk.Button(
            toolbar,
            text="💾 Save Encrypted",
            font=("Segoe UI", 9, "bold"),
            bg="#16A34A",
            fg="#FFFFFF",
            activebackground="#15803D",
            activeforeground="#FFFFFF",
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=5,
            command=self.manual_save,
        ).pack(side="right")

        # Text Area
        editor_frame = tk.Frame(self.root, bg="#1E293B", padx=14, pady=10)
        editor_frame.pack(fill="both", expand=True)

        self.text_area = scrolledtext.ScrolledText(
            editor_frame,
            wrap="word",
            font=("Consolas", 11),
            bg="#0F172A",
            fg="#F1F5F9",
            insertbackground="#38BDF8",
            relief="flat",
            padx=12,
            pady=12,
        )
        self.text_area.pack(fill="both", expand=True)
        self.text_area.insert("1.0", initial_text)
        self.text_area.focus_set()

        # Status Bar with Live Auto-Lock Countdown
        status_bar = tk.Frame(self.root, bg="#0F172A", padx=14, pady=6)
        status_bar.pack(fill="x")

        self.status_label = tk.Label(
            status_bar,
            text="Status: Decrypted in memory | Stored encrypted on disk",
            font=("Segoe UI", 9),
            fg="#94A3B8",
            bg="#0F172A",
        )
        self.status_label.pack(side="left")

        self.timer_label = tk.Label(
            status_bar,
            text=f"Auto-lock in: {self.remaining_seconds}s",
            font=("Segoe UI", 9, "bold"),
            fg="#FBBF24",
            bg="#0F172A",
        )
        self.timer_label.pack(side="right")

        # Start the 1-second countdown loop
        self.tick_inactivity_timer()

    # ---------------------------------------------------------
    # SAVE & INACTIVITY AUTO-LOCK LOGIC
    # ---------------------------------------------------------
    def manual_save(self):
        if not self.is_unlocked:
            return
        content = self.text_area.get("1.0", "end-1c")
        if self.encrypt_and_save(content):
            self.status_label.config(text="Status: Saved & encrypted successfully!", fg="#4ADE80")

    def manual_lock(self):
        """Auto-saves current edits, clears plaintext from UI, and returns to lock screen."""
        if self.is_unlocked:
            content = self.text_area.get("1.0", "end-1c")
            self.encrypt_and_save(content)
            self.text_area.delete("1.0", tk.END)
        self.show_lock_screen()

    def reset_inactivity_timer(self, _event=None):
        """Resets the 60-second timer whenever user activity occurs in the window."""
        if self.is_unlocked:
            self.remaining_seconds = AUTO_LOCK_SECONDS
            if hasattr(self, "timer_label") and self.timer_label.winfo_exists():
                self.timer_label.config(text=f"Auto-lock in: {self.remaining_seconds}s", fg="#FBBF24")

    def tick_inactivity_timer(self):
        """Decrements the countdown each second and triggers auto-lock at 0."""
        if not self.is_unlocked:
            return

        if self.remaining_seconds <= 0:
            self.manual_lock()
            return

        color = "#F87171" if self.remaining_seconds <= 10 else "#FBBF24"
        self.timer_label.config(text=f"Auto-lock in: {self.remaining_seconds}s", fg=color)
        self.remaining_seconds -= 1
        self.timer_job = self.root.after(1000, self.tick_inactivity_timer)

    def on_close(self):
        """Saves encrypted notes automatically if closed while unlocked."""
        if self.is_unlocked and hasattr(self, "text_area"):
            content = self.text_area.get("1.0", "end-1c")
            self.encrypt_and_save(content)
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureNotesApp(root)
    root.mainloop()