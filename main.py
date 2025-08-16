import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QProgressBar
)
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtCore import Qt, QTimer
from auth import AuthWindow
from dashboard import USBBlockDashboard


class GetStartedScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Firewall - Get Started")
        self.resize(600,600)
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        self.setStyleSheet("background-color: white; border: 2px solid #e74c3c; border-radius: 15px;")

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Top Banner
        top_banner = QLabel("Get Full Protection Now")
        top_banner.setAlignment(Qt.AlignCenter)
        top_banner.setStyleSheet(
            "background-color: #c0392b; color: white; font-size: 16px; padding: 8px; "
            "border-top-left-radius: 12px; border-top-right-radius: 12px;"
        )
        main_layout.addWidget(top_banner)

        # Info Layout
        logo_and_info_layout = QHBoxLayout()

        # Image
        self.firewall_image_label = QLabel()
        pixmap = QPixmap("C:\\usb_firewall_project\\assests\\usb_firewall.png")
        self.firewall_image_label.setPixmap(pixmap.scaled(250, 200, Qt.KeepAspectRatio))
        self.firewall_image_label.setAlignment(Qt.AlignCenter)
        self.firewall_image_label.setStyleSheet("border: none;")
        logo_and_info_layout.addWidget(self.firewall_image_label)

        # Info Text
        info_layout = QVBoxLayout()
        title = QLabel("USB Firewall")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #e74c3c;")
        info_layout.addWidget(title)

        version = QLabel("Version 1.0.0")
        version.setStyleSheet("font-size: 12px; color: black;")
        info_layout.addWidget(version)

        message = QLabel("Welcome! Secure your system\nfrom threats and unauthorized USB devices.")
        message.setStyleSheet("font-size: 12px; color: #2c3e50;")
        message.setWordWrap(True)
        info_layout.addWidget(message)

        logo_and_info_layout.addLayout(info_layout)
        main_layout.addLayout(logo_and_info_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(10)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #c0392b;
                border-radius: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2ecc71;
                width: 20px;
            }
        """)
        main_layout.addWidget(self.progress_bar)

        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(50)

        # Buttons
        button_layout = QHBoxLayout()

        login_btn = QPushButton("Login")
        login_btn.setFixedHeight(40)
        login_btn.setStyleSheet(self.button_style())
        login_btn.clicked.connect(lambda: self.open_auth("login"))

        signup_btn = QPushButton("Sign Up")
        signup_btn.setFixedHeight(40)
        signup_btn.setStyleSheet(self.button_style())
        signup_btn.clicked.connect(lambda: self.open_auth("signup"))

        guest_btn = QPushButton("Guest Mode")
        guest_btn.setFixedHeight(40)
        guest_btn.setStyleSheet(self.button_style())
        guest_btn.clicked.connect(lambda: self.open_auth("guest"))

        button_layout.addWidget(login_btn)
        button_layout.addWidget(signup_btn)
        button_layout.addWidget(guest_btn)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def button_style(self):
        return """
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border-radius: 10px;
                padding: 10px 20px;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """

    def update_progress(self):
        value = self.progress_bar.value()
        if value < 100:
            self.progress_bar.setValue(value + 1)
        else:
            self.timer.stop()

    def open_auth(self, mode):
        self.hide()
        self.auth_window = AuthWindow(mode=mode)
        result = self.auth_window.exec_()
        if result and self.auth_window.username_value:
            username = self.auth_window.username_value
            print(f"{mode.capitalize()} successful. Logged in as: {username}")
            self.dashboard = USBBlockDashboard(username )
            self.dashboard.show()
            self.hide()
            
        else:
            print(f"{mode.capitalize()} cancelled or failed.")
            self.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GetStartedScreen()
    window.show()
    sys.exit(app.exec_())
