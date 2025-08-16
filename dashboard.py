import sys
import os
import json
import platform
import psutil
import sqlite3
from datetime import datetime

from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QApplication,
    QGridLayout, QDesktopWidget, QFrame, QPushButton, QStackedWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QFileDialog,
    QLineEdit, QGroupBox, QComboBox, QDialog, QFormLayout
)
from PyQt5.QtGui import QPixmap, QCursor, QPainter, QPen, QColor, QKeySequence
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect, QTimer


# Try to import WMI for better USB details on Windows (optional)
try:
    import wmi  # type: ignore
    HAS_WMI = True
except Exception:
    HAS_WMI = False

# Try to import reportlab for PDF export
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except Exception:
    HAS_REPORTLAB = False


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Password")
        self.setFixedSize(400, 250)
        
        layout = QVBoxLayout()
        
        form = QFormLayout()
        self.old_password = QLineEdit()
        self.old_password.setEchoMode(QLineEdit.Password)
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        
        form.addRow("Old Password:", self.old_password)
        form.addRow("New Password:", self.new_password)
        form.addRow("Confirm Password:", self.confirm_password)
        
        layout.addLayout(form)
        
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red;")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)
        
        button_box = QHBoxLayout()
        button_box.addStretch()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_box.addWidget(self.cancel_btn)
        
        self.change_btn = QPushButton("Change Password")
        self.change_btn.clicked.connect(self.validate_password)
        button_box.addWidget(self.change_btn)
        
        layout.addLayout(button_box)
        self.setLayout(layout)
    
    def validate_password(self):
        old_pass = self.old_password.text()
        new_pass = self.new_password.text()
        confirm_pass = self.confirm_password.text()
        
        if not old_pass or not new_pass or not confirm_pass:
            self.error_label.setText("All fields are required!")
            self.error_label.setVisible(True)
            return
            
        if new_pass != confirm_pass:
            self.error_label.setText("New passwords don't match!")
            self.error_label.setVisible(True)
            return
            
        # In a real app, you would verify old password against stored hash
        # For demo, we'll just accept any old password
        self.accept()


class ClickableMenuItem(QWidget):
    """
    Clickable menu item with hover/click 3D-like animation.
    We capture the widget geometry on showEvent so animations work reliably
    even though items are placed inside layouts.
    """
    def __init__(self, text, icon_path, index, callback):
        super().__init__()
        self.index = index
        self.callback = callback
        self.is_hovered = False
        self.original_geometry = None
        self.anim = None

        icon_label = QLabel()
        icon_label.setPixmap(QPixmap(icon_path).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("border:none;")

        text_label = QLabel(text)
        text_label.setAlignment(Qt.AlignCenter)
        text_label.setWordWrap(True)
        text_label.setStyleSheet("border: none; font-size: 15px; font-weight:bold; font-family: 'Times New Roman';")

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        layout.addWidget(icon_label)
        layout.addWidget(text_label)

        self.setLayout(layout)
        self.setFixedWidth(140)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setStyleSheet("background-color: transparent;")

    def showEvent(self, event):
        QTimer.singleShot(10, self._capture_geometry)
        super().showEvent(event)

    def _capture_geometry(self):
        if self.original_geometry is None:
            self.original_geometry = self.geometry()

    def enterEvent(self, event):
        self.is_hovered = True
        self.animate_scale(1.06)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.is_hovered = False
        self.animate_scale(1.0)
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        self.animate_scale(0.94, quick=True)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if self.is_hovered:
            self.animate_scale(1.06)
        else:
            self.animate_scale(1.0)
        if callable(self.callback):
            QTimer.singleShot(20, lambda: self.callback(self.index))
        super().mouseReleaseEvent(event)

    def animate_scale(self, scale_factor, quick=False):
        if not self.original_geometry:
            self._capture_geometry()
            if not self.original_geometry:
                return

        orig = self.original_geometry
        w = orig.width()
        h = orig.height()
        new_w = int(w * scale_factor)
        new_h = int(h * scale_factor)

        x_offset = (w - new_w) // 2
        y_offset = (h - new_h) // 2

        new_geometry = QRect(
            orig.x() + x_offset,
            orig.y() + y_offset,
            new_w,
            new_h
        )

        if self.anim and self.anim.state() == QPropertyAnimation.Running:
            self.anim.stop()

        self.anim = QPropertyAnimation(self, b"geometry")
        self.anim.setDuration(110 if quick else 220)
        self.anim.setStartValue(self.geometry())
        self.anim.setEndValue(new_geometry)
        self.anim.setEasingCurve(QEasingCurve.OutCubic if not quick else QEasingCurve.OutQuad)
        self.anim.start()


class LineOverlayWidget(QWidget):
    def __init__(self, block_icon, summary_icons, layout, parent=None):
        super().__init__(parent)
        self.block_icon = block_icon
        self.summary_icons = summary_icons

        container = QWidget()
        container.setLayout(layout)

        wrapper = QVBoxLayout()
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.addWidget(container)
        self.setLayout(wrapper)

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self.block_icon or not self.summary_icons:
            return

        painter = QPainter(self)
        pen = QPen(QColor(0, 0, 0), 2)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(pen)

        block_center = self.block_icon.mapTo(self, self.block_icon.rect().center())
        for widget, _, _ in self.summary_icons:
            icon_center = widget.mapTo(self, widget.rect().center())
            painter.drawLine(block_center, icon_center)
            painter.setBrush(QColor(0, 0, 0))
            painter.drawEllipse(icon_center, 3, 3)
            painter.drawEllipse(block_center, 3, 3)
        painter.end()


class HotkeyInput(QLineEdit):
    """Custom input for capturing hotkey combinations"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setAlignment(Qt.AlignCenter)
        self.setPlaceholderText("Press a key combination...")
        self.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
                background-color: #1976D2;
                color: white;
            }
        """)
        self.key_sequence = QKeySequence()
        
    def keyPressEvent(self, event):
        key = event.key()
        modifiers = event.modifiers()
        
        # Ignore modifier-only presses
        if key in (Qt.Key_Shift, Qt.Key_Control, Qt.Key_Alt, Qt.Key_Meta):
            return
            
        # Build the key sequence
        self.key_sequence = QKeySequence(modifiers + key)
        self.setText(self.key_sequence.toString())
        
    def get_hotkey(self):
        return self.key_sequence.toString()


class RegisterNowPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet("""
            QWidget {
                font-family: Arial;
                font-size: 12pt;
            }
            QFrame {
                border: 2px solid #dcdcdc;
                border-radius: 8px;
                padding: 10px;
                background: #fafafa;
            }
            QPushButton {
                background-color: orange;
                color: white;
                font-weight: bold;
                border-radius: 6px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #ff9900;
            }
            QLineEdit {
                border: 1px solid gray;
                border-radius: 5px;
                padding: 5px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(20)

        # --- Register Now Section ---
        reg_frame = QFrame()
        reg_layout = QVBoxLayout()
        reg_label = QLabel(
            "<b>Register Now:</b><br>"
            "Buy USB Block by clicking the Buy Now button or use the registration area "
            "to enter your registration details provided in an email after purchase."
        )
        reg_label.setWordWrap(True)
        reg_layout.addWidget(reg_label)
        reg_frame.setLayout(reg_layout)
        reg_label.setStyleSheet("border:none;")

        # --- Buy Online Section ---
        buy_frame = QFrame()
        buy_layout = QVBoxLayout()
        buy_label = QLabel(
            "<b>Buy Online:</b><br>"
            "You can make your payment through Credit/Debit Cards, PayPal, Check, Bank Wires "
            "or Purchase Orders. Please click 'Buy Now' to learn more."
        )
        buy_label.setWordWrap(True)
        buy_label.setStyleSheet("border:none;")

        buy_button = QPushButton("Buy Now")
        buy_button.clicked.connect(self.on_buy_now)
        buy_layout.addWidget(buy_label)
        buy_layout.addWidget(buy_button, alignment=Qt.AlignCenter)
        buy_frame.setLayout(buy_layout)

        # --- Registration Section ---
        reg_form_frame = QFrame()
        reg_form_layout = QVBoxLayout()

        reg_label2 = QLabel(
            "<b>Registration:</b><br>"
            "When you purchase USB Block, you get an email with a unique serial number "
            "and a registration key. Enter them below to activate the full version."
        )
        reg_label2.setWordWrap(True)
        reg_label2.setStyleSheet("border:none;")

        form = QFormLayout()
        form.setSpacing(10)
        self.serial_input = QLineEdit()
        self.serial_input.setPlaceholderText("Enter your serial number")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter your registration key")
        form.addRow("Serial Number:", self.serial_input)
        form.addRow("Registration Key:", self.key_input)

        submit_btn = QPushButton("Submit Registration")
        submit_btn.setStyleSheet("background-color: #d32f2f; color: white;")
        submit_btn.clicked.connect(self.on_submit_registration)

        reg_form_layout.addWidget(reg_label2)
        reg_form_layout.addLayout(form)
        reg_form_layout.addWidget(submit_btn, alignment=Qt.AlignCenter)
        reg_form_frame.setLayout(reg_form_layout)

        # --- Add sections to main layout ---
        layout.addWidget(reg_frame)
        layout.addWidget(buy_frame)
        layout.addWidget(reg_form_frame)
        layout.addStretch()

        self.setLayout(layout)

    def on_buy_now(self):
        # Create a borderless message box
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Buy Now")
        msg_box.setText("Redirecting to purchase website...\n\n"
                       "In a real application, this would open your web browser to the purchase page.")
        msg_box.setStyleSheet("""
            QMessageBox {
                border: none;
            }
            QLabel {
                min-width: 300px;
            }
        """)
        msg_box.exec_()

    def on_submit_registration(self):
        serial = self.serial_input.text().strip()
        key = self.key_input.text().strip()

        if not serial or not key:
            QMessageBox.warning(self, "Registration Error", "Please enter both serial number and registration key")
            return

        # In a real app, you would validate the serial and key here
        QMessageBox.information(
            self, 
            "Registration Successful", 
            "Thank you for registering USB Block!\n\n"
            "Your product has been successfully activated."
        )
        self.parent().add_log_to_db("Product Registration", "Successfully registered")


class USBBlockDashboard(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setFixedSize(1100, 900)
        self.setWindowTitle(f"USB Defender - {self.username}")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: white;")
        self.summary_icons = []

        # --- DB path & init ---
        self.db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usb_reports.db")
        self.init_db()

        # --- Authorized devices store (JSON on disk) ---
        self.auth_store_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authorized_devices.json")
        self.authorized_devices = self.load_authorized_devices()

        # --- Real-time USB detection state ---
        self.current_usb_set = set()  # mountpoints we see right now

        self.init_ui()
        self.center_window()

        # Start real-time detection (polling every 1s)
        self.usb_timer = QTimer(self)
        self.usb_timer.timeout.connect(self.check_usb_changes)
        self.usb_timer.start(1000)

    # ---------- DB ----------
    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    datetime TEXT NOT NULL,
                    event TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            # Create table for hack attempts if it doesn't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hack_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    datetime TEXT NOT NULL,
                    attempt_type TEXT NOT NULL,
                    details TEXT
                )
            """)
            
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Unable to initialize database:\n{e}")

    def add_log_to_db(self, event: str, status: str):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO reports (datetime, event, status) VALUES (?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event, status)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Could not write log:\n{e}")
            return
        # Auto-refresh reports table if visible
        if getattr(self, "reports_table", None):
            self.load_reports_from_db()

    def add_hack_attempt(self, attempt_type: str, details: str = ""):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO hack_attempts (datetime, attempt_type, details) VALUES (?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), attempt_type, details)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Could not log hack attempt:\n{e}")

    def load_hack_attempts(self, limit: int = 100):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT datetime, attempt_type, details FROM hack_attempts ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cur.fetchall()
            conn.close()
            return rows
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Could not load hack attempts:\n{e}")
            return []

    def clear_hack_attempts(self):
        """Delete all hack attempts from DB."""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("DELETE FROM hack_attempts")
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Could not clear hack attempts:\n{e}")
            return False

    def load_reports_from_db(self, limit: int = 100):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT datetime, event, status FROM reports ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cur.fetchall()
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Could not load reports:\n{e}")
            return

        # Clear current table and repopulate
        self.reports_table.setRowCount(0)
        for r, row in enumerate(rows):
            self.reports_table.insertRow(r)
            for c, val in enumerate(row):
                self.reports_table.setItem(r, c, QTableWidgetItem(str(val)))

    def clear_all_reports(self):
        """Delete all reports from DB."""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("DELETE FROM reports")
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Could not clear Reports:\n{e}")

    # ---------- Authorized devices persistence ----------
    def load_authorized_devices(self):
        if os.path.exists(self.auth_store_path):
            try:
                with open(self.auth_store_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []  # list of dicts: {serial, type, name}

    def save_authorized_devices(self):
        try:
            with open(self.auth_store_path, "w", encoding="utf-8") as f:
                json.dump(self.authorized_devices, f, indent=2)
        except Exception:
            pass

    # ---------- Real-time USB detection ----------
    def list_connected_usb_mounts(self):
        mounts = []
        for p in psutil.disk_partitions(all=False):
            opts = (p.opts or "").lower()
            if "removable" in opts or "/media" in p.mountpoint or "/run/media" in p.mountpoint or "/mnt" in p.mountpoint:
                mounts.append(p.mountpoint)
        return set(mounts)

    def get_connected_usb_info(self):
        """
        Returns a list of dicts for connected USBs with best-effort details:
        [{serial, type, name, mount}]
        """
        info_list = []
        mounts = self.list_connected_usb_mounts()

        # Basic, cross-platform fallback using mountpoint as ID
        for m in mounts:
            info = {"serial": m, "type": "USB Storage", "name": os.path.basename(m) or m, "mount": m}
            info_list.append(info)

        # On Windows, try to enrich with WMI (if available)
        if platform.system().lower().startswith("win") and HAS_WMI:
            try:
                c = wmi.WMI()
                for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                    serial = getattr(disk, "SerialNumber", "") or getattr(disk, "PNPDeviceID", "")
                    model = getattr(disk, "Model", "USB Storage")
                    # Leave mount association naive (we already have mounts)
                    for i in range(len(info_list)):
                        if info_list[i]["serial"] == info_list[i]["mount"]:
                            info_list[i]["serial"] = serial or info_list[i]["serial"]
                            info_list[i]["type"] = "USB Storage"
                            info_list[i]["name"] = model
            except Exception:
                pass

        return info_list

    def check_usb_changes(self):
        """Poll for USB insertion/removal and react if an unknown device appears (and log to DB)."""
        new_set = self.list_connected_usb_mounts()
        inserted = new_set - self.current_usb_set
        removed = self.current_usb_set - new_set
        self.current_usb_set = new_set

        if inserted:
            connected = self.get_connected_usb_info()
            for dev in connected:
                if dev["mount"] in inserted:
                    if not self.is_authorized(dev["serial"]):
                        # Unknown device detected -> Blocked (log)
                        self.add_log_to_db(f"Unauthorized Device Detected ({dev.get('name','Unknown')})", "Blocked")
                        QMessageBox.warning(
                            self,
                            "USB Detected",
                            f"An unrecognized USB device was detected:\n\n"
                            f"Name: {dev['name']}\nMount: {dev['mount']}\n\n"
                            f"This device is NOT in your authorized list.\n"
                            f"Please scan it before use or add it to Authorized Devices."
                        )
                    else:
                        # Known device -> Allowed (log)
                        self.add_log_to_db(f"USB Device Connected ({dev.get('name','USB')})", "Allowed")

        if removed:
            for m in removed:
                self.add_log_to_db(f"USB Device Removed ({os.path.basename(m) or m})", "Removed")

        # Keep Authorized Devices table fresh if that page is visible
        if getattr(self, "auth_table", None):
            self.populate_authorized_table()

    def is_authorized(self, serial):
        return any(item.get("serial") == serial for item in self.authorized_devices)

    # ---------- UI ----------
    def center_window(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # --- Title Bar (taller) ---
        title_bar = QHBoxLayout()
        title_bar.setContentsMargins(5, 5, 5, 5)

        app_name = QLabel(f"USB Defender 1.1.1 Beta | Welcome, {self.username}")
        app_name.setStyleSheet("color: white; font-weight: bold; font-size: 18px;")
        title_bar.addWidget(app_name)
        title_bar.addStretch()

        minimize_btn = QPushButton("-")
        minimize_btn.setFixedSize(26, 26)
        minimize_btn.setStyleSheet("color: white; background: none; border: none; font-size: 16px;")
        minimize_btn.clicked.connect(self.showMinimized)

        close_btn = QPushButton("X")
        close_btn.setFixedSize(26, 26)
        close_btn.setStyleSheet("color: white; background: none; border: none; font-size: 16px;")
        close_btn.clicked.connect(self.close)

        title_bar.addWidget(minimize_btn)
        title_bar.addWidget(close_btn)

        title_bar_widget = QWidget()
        title_bar_widget.setStyleSheet("background-color: #c32020; border-top: 5px solid darkred; border-radius: 6px;")
        title_bar_widget.setLayout(title_bar)
        main_layout.addWidget(title_bar_widget)

        # --- Top Menu (single container box) ---
        menu_layout = QHBoxLayout()
        menu_layout.setSpacing(10)
        menu_layout.setContentsMargins(12, 12, 12, 12)

        menu_items = [
            ("Detailed Summary", "icons/detailed_summary.png"),
            ("Control Center", "icons/control_center.png"),
            ("Authorized Devices", "icons/authorized_devices.png"),
            ("Reports & Logs", "icons/report_logs.png"),
            ("Program Options", "icons/program_options.png"),
            ("Register Now!", "icons/Registered.png")
        ]

        self.menu_items_widgets = []
        for idx, (text, icon) in enumerate(menu_items):
            item = ClickableMenuItem(text, icon, idx, self.switch_page)
            menu_layout.addWidget(item)
            self.menu_items_widgets.append(item)

        menu_widget = QWidget()
        menu_widget.setStyleSheet("""
            background-color: #ffecec;
            border: 2px solid #f2b6b6;
            border-radius: 10px;
        """)
        menu_widget.setLayout(menu_layout)
        main_layout.addWidget(menu_widget)

        # --- Pages stack ---
        self.stack = QStackedWidget()
        self.stack.addWidget(self.create_detailed_summary_page())   # 0
        self.stack.addWidget(self.create_control_center_page())     # 1
        self.stack.addWidget(self.create_authorized_devices_page()) # 2
        self.stack.addWidget(self.create_reports_logs_page())       # 3
        self.stack.addWidget(self.create_program_options_page())    # 4
        self.stack.addWidget(RegisterNowPage(self))                 # 5 - Updated to use the new RegisterNowPage

        main_layout.addWidget(self.stack)
        self.setLayout(main_layout)

    def create_detailed_summary_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        summary_title = QLabel("Detailed Summary:")
        summary_title.setStyleSheet("font-weight: bold; font-size: 20px; padding: 5px; text-decoration:underline;")
        layout.addWidget(summary_title)

        center_grid = QGridLayout()
        center_grid.setContentsMargins(10, 10, 10, 10)

        items = [
            ("USB Devices", "icons/usb.png", 0, 0),
            ("Disc / Floppy Drives", "icons/disc.png", 0, 2),
            ("Network PCs / Drives", "icons/network.png", 2, 0),
            ("Non-System Drives", "icons/hdd.png", 2, 2)
        ]
        self.summary_icons = []
        for name, icon, row, col in items:
            icon_label = QLabel()
            icon_label.setPixmap(QPixmap(icon).scaled(70, 70, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            icon_label.setAlignment(Qt.AlignCenter)
            font_size = "16px" if name == "USB Devices" else "12px"
            text = QLabel(f"<b>{name}</b><br><u><b>Status</b></u> : "
                          f"<span style='color: green; font-size: 10px'>Allowed</span>")
            text.setAlignment(Qt.AlignCenter)
            text.setStyleSheet(f"font-size: {font_size}; font-family: 'Times New Roman';")
            layout_v = QVBoxLayout()
            layout_v.addWidget(icon_label)
            layout_v.addWidget(text)
            widget = QWidget()
            widget.setLayout(layout_v)
            center_grid.addWidget(widget, row, col)
            self.summary_icons.append((widget, row, col))

        self.block_icon = QLabel()
        # Make center image larger
        self.block_icon.setPixmap(QPixmap("icons/block.png").scaled(130, 130, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.block_icon.setAlignment(Qt.AlignCenter)
        center_grid.addWidget(self.block_icon, 1, 1)

        overlay_widget = LineOverlayWidget(self.block_icon, self.summary_icons, center_grid)
        layout.addWidget(overlay_widget)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #aaa; margin: 20px 20px;")
        layout.addWidget(line)

        logs_title = QLabel("Reports & logs Summary:")
        logs_title.setStyleSheet("font-weight: bold; font-size: 20px; padding: 1px 10px; text-decoration:underline;")
        layout.addWidget(logs_title)

        logs_layout = QHBoxLayout()
        logs_layout.setContentsMargins(10, 0, 10, 10)
        logs_layout.setSpacing(20)

        reports = [
            ("USB Devices Report", ["Times Plugged-in: 0", "USB  Blocked: 0", "Authorized USBs: 0"]),
            ("Disc Drives Report", ["Times Inserted: 0", "Discs  Blocked: 0", "Authorized DISCs: 0"]),
            ("Network Access Report", ["Times Accessed: 0", "Network Blocked: 0", "Authorized Networks:0"]),
            ("Non-System Drives Report", ["Times Accessed: 0", "Drives Blocked: 0", "Authorized Drives: 0"])
        ]

        for i, (title, lines) in enumerate(reports):
            section_layout = QVBoxLayout()
            label = QLabel(f"<b>{title}</b>")
            section_layout.addWidget(label)
            for line in lines:
                l = QLabel(line)
                l.setStyleSheet("font-size: 14px;")
                section_layout.addWidget(l)
            section_widget = QWidget()
            section_widget.setLayout(section_layout)
            logs_layout.addWidget(section_widget)

            if i < len(reports) - 1:
                vline = QFrame()
                vline.setFrameShape(QFrame.VLine)
                vline.setStyleSheet("color: #aaa;")
                logs_layout.addWidget(vline)

        view_reports = QLabel("<a href='#'>View Full Reports...</a>")
        view_reports.setOpenExternalLinks(False)
        view_reports.setCursor(QCursor(Qt.PointingHandCursor))
        view_reports.setStyleSheet("color: blue; font-size: 14px; padding-top: 5px;")
        view_reports.linkActivated.connect(lambda: self.switch_page(3))  # Switch to reports page
        logs_layout.addWidget(view_reports)

        logs_widget = QWidget()
        logs_widget.setLayout(logs_layout)
        layout.addWidget(logs_widget)

        return page

    def create_reports_logs_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        title = QLabel("Reports & Logs")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; text-decoration: underline; margin-bottom: 8px;")
        layout.addWidget(title)

        # Table (now bound to DB)
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(3)
        self.reports_table.setHorizontalHeaderLabels(["Date & Time", "Event", "Status"])
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.reports_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #f2b6b6;
                font-size: 14px;
                gridline-color: #ddd;
            }
            QHeaderView::section {
                background-color: #ffecec;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.reports_table)

        # Buttons row
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.btn_download_pdf = QPushButton("Download Report as PDF")
        self.btn_download_pdf.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_download_pdf.setStyleSheet("""
            QPushButton {
                background-color: green;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #0a8a0a; }
        """)
        self.btn_download_pdf.clicked.connect(self.download_report_pdf)
        btn_row.addWidget(self.btn_download_pdf)

        # Clear All Reports button (with confirmation)
        self.btn_clear_reports = QPushButton("Clear All Reports")
        self.btn_clear_reports.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_clear_reports.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 8px 14px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #b71c1c; }
        """)
        self.btn_clear_reports.clicked.connect(self.confirm_and_clear_logs)
        btn_row.addWidget(self.btn_clear_reports)

        layout.addLayout(btn_row)

        # Initial load from DB
        self.load_reports_from_db()

        return page

    def download_report_pdf(self):
        """Export logs to PDF with a Chrome-like Save As dialog (always downloads, even if no rows)."""
        if not HAS_REPORTLAB:
            QMessageBox.warning(
                self, "Missing Dependency",
                "PDF export requires 'reportlab'. Install it with:\n\npip install reportlab"
            )
            return

        today = datetime.now().strftime("%Y-%m-%d")
        default_name = f"usb_reports_{today}.pdf"

        # Fetch current table data
        rows = self.reports_table.rowCount()
        data = [["Date & Time", "Event", "Status"]]

        if rows > 0:
            for r in range(rows):
                row_vals = [
                    self.reports_table.item(r, 0).text() if self.reports_table.item(r, 0) else "",
                    self.reports_table.item(r, 1).text() if self.reports_table.item(r, 1) else "",
                    self.reports_table.item(r, 2).text() if self.reports_table.item(r, 2) else "",
                ]
                data.append(row_vals)

        # --- Save As dialog (Chrome-like download) ---
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save USB Report",
            default_name,
            "PDF Files (*.pdf)",
            options=options
        )
        if not file_path:  # user cancelled
            return
        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"

        try:
            doc = SimpleDocTemplate(file_path, pagesize=A4)
            elements = []

            styles = getSampleStyleSheet()
            elements.append(Paragraph("USB Defender - Reports & Logs", styles['Title']))
            elements.append(Paragraph(datetime.now().strftime("Generated on %Y-%m-%d %H:%M:%S"), styles['Normal']))
            elements.append(Spacer(1, 12))

            if rows > 0:
                # Build logs table
                table = Table(data, repeatRows=1)
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ffecec")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(table)
            else:
                # If no rows, just say so
                elements.append(Paragraph("No reports available.", styles['Normal']))

            doc.build(elements)
            QMessageBox.information(self, "Export PDF", f"Report exported:\n{file_path}")

        except Exception as e:
            QMessageBox.warning(self, "PDF Error", f"Failed to generate PDF:\n{e}")

    def confirm_and_clear_logs(self):
        """Ask user confirmation and clear logs if confirmed."""
        reply = QMessageBox.question(
            self,
            "Clear All Reports",
            "Are you sure you want to clear all reports? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # Clear DB
            self.clear_all_reports()
            # Clear UI table
            if getattr(self, "reports_table", None):
                self.reports_table.setRowCount(0)
            QMessageBox.information(self, "Reports Cleared", "All reports have been cleared.")

    def create_control_center_page(self):
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(10, 10, 10, 10)
        page_layout.setSpacing(2)

        title = QLabel("Control Center:")
        title.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        title.setStyleSheet("font-size: 25px; font-weight: bold; margin-bottom: 1px; text-decoration: underline ")
        page_layout.addWidget(title)

        desc = QLabel(
            "Block devices you need protection from. Every unauthorized USB Drive, Disc / Floppy, Network PC or Partition will be blocked. "
            "Check / Uncheck the devices you need to protect your PC from. Also Scan the USB file from Unknown Threats and malwares That can harm your System."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("font-size:20px;")
        page_layout.addWidget(desc)
        page_layout.setSpacing(2)

        controls = [
            ("icons/usb.png", "Block USB Devices", "Stop Unauthorized USB Drives, External Drives and Memory Cards."),
            ("icons/disc.png", "Block Discs & Floppy Drives", "Stop Unauthorized CDs, DVDs, Bluray, HD and Floppy Drives."),
            ("icons/network.png", "Block Network Access", "Stop Unauthorized Network Access to other computers."),
            ("icons/hdd.png", "Block Non-System Drives", "Stop Unauthorized Drives and Partitions except System Drive."),
        ]

        for icon_path, title_text, desc_text in controls:
            item_widget = QWidget()
            item_layout = QHBoxLayout(item_widget)
            item_layout.setContentsMargins(20, 20, 20, 20)
            item_layout.setSpacing(20)
            item_widget.setStyleSheet("border:none;")

            chk = QCheckBox()
            chk.setFixedSize(30, 30)
            item_layout.addWidget(chk)
            chk.setStyleSheet("border:none;")

            icon_label = QLabel()
            icon_label.setPixmap(QPixmap(icon_path).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            item_layout.addWidget(icon_label)
            icon_label.setStyleSheet("border:none; background:transparent;")

            text_layout = QVBoxLayout()
            title_lbl = QLabel(title_text)
            title_lbl.setStyleSheet("font-weight: bold; font-size: 14px; border: none; ")
            desc_lbl = QLabel(desc_text)
            desc_lbl.setStyleSheet("color: gray; font-size: 12px; border:none;")
            text_layout.addWidget(title_lbl)
            text_layout.addWidget(desc_lbl)
            item_layout.addLayout(text_layout)

            status_lbl = QLabel("Protection: Disabled")
            status_lbl.setStyleSheet("color: red; font-weight: bold; border:none;")
            item_layout.addStretch()
            item_layout.addWidget(status_lbl)

            def toggle_status(checked, lbl=status_lbl):
                lbl.setText("Protection: Enabled" if checked else "Protection: Disabled")
                lbl.setStyleSheet("color: green; font-weight: bold; border:none;" if checked else "color: red; font-weight: bold; border:none;")
            chk.stateChanged.connect(lambda state, lbl=status_lbl: toggle_status(state == Qt.Checked, lbl))

            item_widget.setStyleSheet("""
                QWidget {
                    background-color: #fff8f8;
                    border: 1px solid #f2b6b6;
                    border-radius: 8px;
                }
            """)
            page_layout.addWidget(item_widget)

        scan_widget = QWidget()
        scan_layout = QHBoxLayout(scan_widget)
        scan_layout.setContentsMargins(10, 10, 10, 10)
        scan_layout.setSpacing(15)

        scan_lbl = QLabel("Scan USB Files:")
        scan_lbl.setStyleSheet("font-size: 20px; font-weight: bold;")
        scan_layout.addWidget(scan_lbl)

        go_green_btn = QPushButton("Scan")
        go_green_btn.setStyleSheet("""
            QPushButton {
                background-color: green;
                color: white;
                font-size: 18px;
                font-weight: bold;
                border-radius: 6px;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #0a8a0a;
            }
        """)

        def scan_usb():
            usb_found = False
            usb_path = None
            for p in psutil.disk_partitions():
                if 'removable' in (p.opts or '').lower() or ('/media' in p.mountpoint or '/mnt' in p.mountpoint):
                    usb_found = True
                    usb_path = p.mountpoint
                    break
            if not usb_found:
                QMessageBox.warning(self, "USB Scan", "No USB device detected!")
                return
            # Optional: log scan start
            self.add_log_to_db(f"Scan Started ({usb_path})", "Started")
            QMessageBox.information(self, "USB Scan", f"Scanning files in {usb_path}...\n(Your AI model will run here.)")

        go_green_btn.clicked.connect(scan_usb)
        scan_layout.addWidget(go_green_btn)
        scan_layout.addStretch()
        page_layout.addWidget(scan_widget)

        return page

    # ---------- Authorized Devices Page ----------
    def create_authorized_devices_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        title_row = QHBoxLayout()
        title = QLabel("Authorized Devices:")
        title.setStyleSheet("font-weight: bold; font-size: 18px; text-decoration: underline;  border:none;")
        title_row.addWidget(title)
        title_row.addStretch()

        # Buttons: Add connected + Remove selected
        self.btn_add_connected = QPushButton("Add Connected USB")
        self.btn_add_connected.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_add_connected.setStyleSheet("""
            QPushButton {
                background-color: #2e7d32;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1f5a22; }
        """)
        self.btn_add_connected.clicked.connect(self.add_connected_usb_as_authorized)

        self.btn_remove_selected = QPushButton("Remove from List")
        self.btn_remove_selected.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_remove_selected.setStyleSheet("""
            QPushButton {
                background-color: #e53935;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #c62828; }
        """)
        self.btn_remove_selected.clicked.connect(self.remove_selected_authorized)

        title_row.addWidget(self.btn_add_connected)
        title_row.addWidget(self.btn_remove_selected)

        title_wrap = QWidget()
        title_wrap.setStyleSheet("""
            background-color: #fff8f8;
            border: 1px solid #f2b6b6;
            border-radius: 8px;
        """)
        tw_layout = QVBoxLayout(title_wrap)
        tw_layout.setContentsMargins(12, 8, 12, 8)
        tw_layout.addLayout(title_row)

        help_lbl = QLabel("To add a device, insert it and click 'Add Connected USB'. To remove items, select rows and press 'Remove from List'.")
        help_lbl.setStyleSheet("font-size: 18px; border:none;")
        tw_layout.addWidget(help_lbl)

        layout.addWidget(title_wrap)

        # Table
        self.auth_table = QTableWidget()
        self.auth_table.setColumnCount(3)
        self.auth_table.setHorizontalHeaderLabels(["Serial No.", "Device Type", "Device Name (with ID)"])
        self.auth_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.auth_table.setSelectionBehavior(self.auth_table.SelectRows)
        self.auth_table.setSelectionMode(self.auth_table.SingleSelection)
        self.auth_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #f2b6b6;
                font-size: 14px;
                gridline-color: #ddd;
            }
            QHeaderView::section {
                background-color: #ffecec;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.auth_table)
        self.populate_authorized_table()
        return page

    def populate_authorized_table(self):
        data = self.authorized_devices
        self.auth_table.setRowCount(len(data))
        for r, item in enumerate(data):
            self.auth_table.setItem(r, 0, QTableWidgetItem(item.get("serial", "")))
            self.auth_table.setItem(r, 1, QTableWidgetItem(item.get("type", "")))
            self.auth_table.setItem(r, 2, QTableWidgetItem(item.get("name", "")))

    def add_connected_usb_as_authorized(self):
        devices = self.get_connected_usb_info()
        if not devices:
            QMessageBox.information(self, "Authorized Devices", "No connected USB storage found.")
            return
        # Pick the first device that isn't authorized yet
        for dev in devices:
            if not self.is_authorized(dev["serial"]):
                self.authorized_devices.append({"serial": dev["serial"], "type": dev["type"], "name": dev["name"]})
                self.save_authorized_devices()
                self.populate_authorized_table()
                self.add_log_to_db(f"Device Authorized ({dev['name']})", "Allowed")
                QMessageBox.information(self, "Authorized Devices", f"Device added:\n\nName: {dev['name']}\nSerial: {dev['serial']}")
                return
        QMessageBox.information(self, "Authorized Devices", "All connected USB devices are already authorized.")

    def remove_selected_authorized(self):
        row = self.auth_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Authorized Devices", "Please select a device to remove.")
            return
        serial = self.auth_table.item(row, 0).text() if self.auth_table.item(row, 0) else ""
        name = self.auth_table.item(row, 2).text() if self.auth_table.item(row, 2) else serial
        self.authorized_devices = [d for d in self.authorized_devices if d.get("serial") != serial]
        self.save_authorized_devices()
        self.populate_authorized_table()
        self.add_log_to_db(f"Device Deauthorized ({name})", "Success")
        QMessageBox.information(self, "Authorized Devices", "Selected device removed from authorized list.")

    # ---------- Program Options Page ----------
    def create_program_options_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # Stealth Options Group
        stealth_group = QGroupBox("Stealth Options")
        stealth_group.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                border: 1px solid #f2b6b6;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
        stealth_layout = QVBoxLayout()
        stealth_layout.setContentsMargins(15, 15, 15, 15)
        stealth_layout.setSpacing(10)

        # Activate Stealth Mode checkbox
        self.stealth_checkbox = QCheckBox("Activate Stealth Mode")
        self.stealth_checkbox.setStyleSheet("font-size: 14px;")
        stealth_layout.addWidget(self.stealth_checkbox)
        
        stealth_desc = QLabel("This will hide USB Block's shortcuts from Start Menu, Desktop and Control Panel.")
        stealth_desc.setStyleSheet("font-size: 12px; color: #555; margin-left: 20px;")
        stealth_layout.addWidget(stealth_desc)

        # Hotkey setting
        hotkey_layout = QHBoxLayout()
        hotkey_label = QLabel("Set Hotkey to Run program in Stealth Mode:")
        hotkey_label.setStyleSheet("font-size: 14px;")
        hotkey_layout.addWidget(hotkey_label)
        
        self.hotkey_input = HotkeyInput()
        self.hotkey_input.setStyleSheet("font-size: 14px;")
        self.hotkey_input.setText("Ctrl+Alt+Shift+A")
        hotkey_layout.addWidget(self.hotkey_input)
        hotkey_layout.addStretch()
        stealth_layout.addLayout(hotkey_layout)

        # No password prompt checkbox
        self.no_prompt_checkbox = QCheckBox("Do not prompt for authorization password")
        self.no_prompt_checkbox.setStyleSheet("font-size: 14px;")
        stealth_layout.addWidget(self.no_prompt_checkbox)

        stealth_group.setLayout(stealth_layout)
        layout.addWidget(stealth_group)

        # General Settings Group
        general_group = QGroupBox("General Settings")
        general_group.setStyleSheet(stealth_group.styleSheet())
        general_layout = QVBoxLayout()
        general_layout.setContentsMargins(15, 15, 15, 15)
        general_layout.setSpacing(10)

        # Protection in Safe Mode checkbox
        self.safe_mode_checkbox = QCheckBox("Protection in Safe Mode")
        self.safe_mode_checkbox.setStyleSheet("font-size: 14px;")
        self.safe_mode_checkbox.setChecked(True)
        general_layout.addWidget(self.safe_mode_checkbox)
        
        safe_mode_desc = QLabel("This will block devices in Windows Safe Mode also.")
        safe_mode_desc.setStyleSheet("font-size: 12px; color: #555; margin-left: 20px;")
        general_layout.addWidget(safe_mode_desc)

        # Activate Master Key checkbox
        self.master_key_checkbox = QCheckBox("Activate Master Key")
        self.master_key_checkbox.setStyleSheet("font-size: 14px;")
        self.master_key_checkbox.setChecked(True)
        general_layout.addWidget(self.master_key_checkbox)
        
        master_key_desc = QLabel("When activated, input your serial number as password after buying.")
        master_key_desc.setStyleSheet("font-size: 12px; color: #555; margin-left: 20px;")
        general_layout.addWidget(master_key_desc)

        # Change Password button
        self.change_password_btn = QPushButton("Change Password")
        self.change_password_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
        """)
        self.change_password_btn.clicked.connect(self.change_password)
        general_layout.addWidget(self.change_password_btn, alignment=Qt.AlignLeft)

        general_group.setLayout(general_layout)
        layout.addWidget(general_group)

        # Hack Attempt Monitoring Group
        hack_group = QGroupBox("Hack Attempt Monitoring")
        hack_group.setStyleSheet(stealth_group.styleSheet())
        hack_layout = QVBoxLayout()
        hack_layout.setContentsMargins(15, 15, 15, 15)
        hack_layout.setSpacing(10)

        # Create table for hack attempts
        self.hack_table = QTableWidget()
        self.hack_table.setColumnCount(3)
        self.hack_table.setHorizontalHeaderLabels(["Date & Time", "Attempt Type", "Details"])
        self.hack_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hack_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #f2b6b6;
                font-size: 14px;
                gridline-color: #ddd;
            }
            QHeaderView::section {
                background-color: #ffecec;
                font-weight: bold;
            }
        """)
        hack_layout.addWidget(self.hack_table)

        # Load hack attempts
        self.load_hack_attempts_table()

        # Clear List button
        clear_hack_btn = QPushButton("Clear Hack Attempts List")
        clear_hack_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #b71c1c;
            }
        """)
        clear_hack_btn.clicked.connect(self.confirm_and_clear_hack_attempts)
        hack_layout.addWidget(clear_hack_btn, alignment=Qt.AlignRight)

        hack_group.setLayout(hack_layout)
        layout.addWidget(hack_group)

        # Bottom buttons layout
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()

        # Logout button
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
        """)
        self.logout_btn.clicked.connect(self.logout)
        bottom_layout.addWidget(self.logout_btn)

        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2e7d32;
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1f5a22;
            }
        """)
        save_btn.clicked.connect(self.save_program_options)
        bottom_layout.addWidget(save_btn)

        layout.addLayout(bottom_layout)
        layout.addStretch()
        return page

    def load_hack_attempts_table(self):
        """Load hack attempts from database into the table"""
        attempts = self.load_hack_attempts()
        self.hack_table.setRowCount(len(attempts))
        
        for row, (dt, attempt_type, details) in enumerate(attempts):
            self.hack_table.setItem(row, 0, QTableWidgetItem(dt))
            self.hack_table.setItem(row, 1, QTableWidgetItem(attempt_type))
            self.hack_table.setItem(row, 2, QTableWidgetItem(details or ""))

    def confirm_and_clear_hack_attempts(self):
        """Ask user confirmation and clear hack attempts if confirmed"""
        reply = QMessageBox.question(
            self,
            "Clear Hack Attempts",
            "Are you sure you want to clear all hack attempt records? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if self.clear_hack_attempts():
                self.load_hack_attempts_table()
                QMessageBox.information(self, "Hack Attempts Cleared", "All hack attempt records have been cleared.")

    def change_password(self):
        """Handle password change based on user type"""
        if self.username.lower() == "guest":
            QMessageBox.information(
                self,
                "Guest Mode",
                "You are in Guest mode and don't have a password to change.\n"
                "Please log in with an administrator account to change passwords."
            )
            return
            
        # For non-guest users, show password change dialog
        dialog = ChangePasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            # In a real app, you would update the password hash here
            QMessageBox.information(
                self,
                "Password Changed",
                "Your password has been changed successfully."
            )
            self.add_hack_attempt("Password Changed", "User changed their password")
            
    def logout(self):
        """Handle logout process"""
        reply = QMessageBox.question(
            self, 
            "Confirm Logout", 
            "Are you sure you want to logout?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # In a real application, you would return to the login screen
            # For this demo, we'll just close the application
            self.close()
            # Add any additional logout logic here
            QMessageBox.information(
                None, 
                "Logged Out", 
                "You have been successfully logged out."
            )

    def save_program_options(self):
        """Save all program options from the settings page."""
        settings = {
            "stealth_mode": self.stealth_checkbox.isChecked(),
            "hotkey": self.hotkey_input.get_hotkey(),
            "no_password_prompt": self.no_prompt_checkbox.isChecked(),
            "safe_mode_protection": self.safe_mode_checkbox.isChecked(),
            "master_key": self.master_key_checkbox.isChecked()
        }
        
        # In a real app, you would save these to a config file or registry
        QMessageBox.information(
            self, 
            "Settings Saved", 
            "Program options have been saved successfully.\n\n"
            f"Stealth Mode: {'Enabled' if settings['stealth_mode'] else 'Disabled'}\n"
            f"Hotkey: {settings['hotkey']}\n"
            f"Safe Mode Protection: {'Enabled' if settings['safe_mode_protection'] else 'Disabled'}"
        )
        
        # Log the settings change
        self.add_log_to_db("Program Options Changed", "Settings Updated")

    # ---------- Helpers ----------
    def create_placeholder_page(self, text):
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel(text)
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(label)
        return page

    def switch_page(self, index):
        if 0 <= index < self.stack.count():
            self.stack.setCurrentIndex(index)
            # Refresh reports when visiting that page
            if index == 3 and getattr(self, "reports_table", None):
                self.load_reports_from_db()
            # Refresh hack attempts when visiting program options
            elif index == 4 and getattr(self, "hack_table", None):
                self.load_hack_attempts_table()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = USBBlockDashboard("Guest")
    win.show()
    sys.exit(app.exec_())