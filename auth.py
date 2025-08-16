from PyQt5.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox
)
from PyQt5.QtCore import Qt
import sqlite3


class AuthWindow(QDialog):
    """
    Authentication dialog for USB Firewall.
    Supports login, signup, and guest modes.
    Tracks guest mode so main window can restrict Control Center.
    """
    def __init__(self, mode="login"):
        super().__init__()
        self.mode = mode
        self.username_value = None  # Stores logged-in / created / guest name
        self.is_guest = False       # True if the logged-in user is guest

        # --- Window Setup ---
        self.setWindowTitle(f"USB Firewall - {mode.capitalize()}")
        if self.mode == "login":
            self.setFixedSize(400, 250)
        elif self.mode == "signup":
            self.setFixedSize(400, 300)
        elif self.mode == "guest":
            self.setFixedSize(400, 200)

        # Styling
        self.setStyleSheet("""
            QDialog {
                background-color: #fff5f5;
                border: 2px solid #c0392b;
                border-radius: 12px;
            }
            QLabel {
                font-size: 13px;
                color: #2c3e50;
            }
            QLineEdit {
                padding: 6px;
                border: 1px solid gray;
                border-radius: 6px;
            }
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 7px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)

        self.init_ui()
        self.init_db()

    def bold_label(self, text, size):
        """Helper to create a bold QLabel with given size."""
        label = QLabel(text)
        label.setStyleSheet(f"font-size: {size}px; font-weight: bold; margin-bottom: 8px;")
        return label

    def init_ui(self):
        """Create UI elements based on mode."""
        layout = QVBoxLayout()

        if self.mode == "login":
            layout.addWidget(self.bold_label("Login to continue:", 20))

            self.username = QLineEdit()
            self.username.setPlaceholderText("Username")
            layout.addWidget(self.username)

            self.password = QLineEdit()
            self.password.setPlaceholderText("Password")
            self.password.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.password)

        elif self.mode == "signup":
            layout.addWidget(self.bold_label("Create a new account:", 20))

            self.username = QLineEdit()
            self.username.setPlaceholderText("Name")
            layout.addWidget(self.username)

            self.password = QLineEdit()
            self.password.setPlaceholderText("Password")
            self.password.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.password)

            self.confirm_password = QLineEdit()
            self.confirm_password.setPlaceholderText("Confirm Password")
            self.confirm_password.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_password)

        elif self.mode == "guest":
            layout.addWidget(self.bold_label("Continue as Guest:", 20))

            self.guest_name = QLineEdit()
            self.guest_name.setPlaceholderText("Enter your name")
            layout.addWidget(self.guest_name)

        # --- Buttons ---
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")
        ok_btn.clicked.connect(self.handle_ok)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def init_db(self):
        """Initialize SQLite database for storing users."""
        self.conn = sqlite3.connect("users.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def handle_ok(self):
        """Handle button clicks for all modes."""
        if self.mode == "login":
            user = self.username.text()
            pw = self.password.text()
            self.cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pw))
            result = self.cursor.fetchone()
            if result:
                self.username_value = user
                self.is_guest = False
                QMessageBox.information(self, "Login Success", f"Welcome back, {user}!")
                self.accept()
            else:
                QMessageBox.warning(self, "Login Failed", "Incorrect username or password.")

        elif self.mode == "signup":
            user = self.username.text()
            pw = self.password.text()
            confirm_pw = self.confirm_password.text()

            if not (user and pw and confirm_pw):
                QMessageBox.warning(self, "Error", "All fields are required.")
                return
            if pw != confirm_pw:
                QMessageBox.warning(self, "Error", "Passwords do not match.")
                return
            try:
                self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pw))
                self.conn.commit()
                self.username_value = user
                self.is_guest = False
                QMessageBox.information(self, "Success", "Account created.")
                self.accept()
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, "Error", "Username already exists.")

        elif self.mode == "guest":
            name = self.guest_name.text()
            if not name:
                QMessageBox.warning(self, "Error", "Name is required.")
                return
            self.username_value = name
            self.is_guest = True  # Mark as guest
            QMessageBox.information(self, "Welcome", f"Hello {name}, you are in guest mode.")
            self.accept()
