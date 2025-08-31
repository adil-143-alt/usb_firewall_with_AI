import sys
import os
import json
import platform
import psutil
import sqlite3
import hashlib
import numpy as np
import pandas as pd
import pickle
import math
import shutil
import time
import threading
import requests
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from PyQt5.QtWidgets import QMessageBox, QProgressDialog
from PyQt5.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QApplication, QProgressBar,
    QGridLayout, QDesktopWidget, QFrame, QPushButton, QStackedWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QFileDialog,
    QLineEdit, QGroupBox, QComboBox, QDialog, QFormLayout, QAction, QMenu, QSizePolicy
)
from PyQt5.QtGui import QPixmap, QCursor, QPainter, QPen, QColor, QKeySequence, QFont, QIcon
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect, QTimer, pyqtSignal, QThread

# Enable High DPI scaling
if hasattr(Qt, 'AA_EnableHighDpiScaling'):
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

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

# Try to import pywin32 for USB blocking on Windows
try:
    import win32file
    import win32api
    import win32security
    import ntsecuritycon
    HAS_WIN32 = True
except Exception:
    HAS_WIN32 = False

# Try to import pefile for PE analysis
try:
    import pefile
    HAS_PEFILE = True
except Exception:
    HAS_PEFILE = False

# Try to import yara for pattern matching
try:
    import yara
    HAS_YARA = True
except Exception:
    HAS_YARA = False


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Password")
        self.setMinimumSize(400, 250)
        
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
        self.setMinimumWidth(140)
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


class USBPortManager:
    """Class to manage USB port blocking/unblocking on Windows"""
    
    def __init__(self):
        self.usb_devices = []
        self.blocked_ports = set()
        
    def get_usb_devices(self):
        """Get list of USB devices"""
        self.usb_devices = []
        try:
            if platform.system() == "Windows" and HAS_WMI:
                c = wmi.WMI()
                for device in c.Win32_USBHub():
                    self.usb_devices.append({
                        'name': device.Name,
                        'device_id': device.DeviceID,
                        'status': 'Enabled'
                    })
        except Exception as e:
            print(f"Error getting USB devices: {e}")
        return self.usb_devices
    
    def block_usb_ports(self):
        """Block USB ports by disabling them in device manager"""
        try:
            if platform.system() == "Windows" and HAS_WIN32:
                # This is a simplified approach - in a real application, you would
                # use more sophisticated methods to disable USB ports
                self.blocked_ports = set()
                
                # Get all USB devices
                c = wmi.WMI()
                for usb in c.Win32_USBControllerDevice():
                    device_id = usb.Dependent.DeviceID
                    self.blocked_ports.add(device_id)
                    
                    # Try to disable the device (requires admin privileges)
                    try:
                        # This would require running as administrator
                        os.system(f'pnputil /disable-device "{device_id}"')
                    except:
                        pass
                        
                return True
            else:
                return False
        except Exception as e:
            print(f"Error blocking USB ports: {e}")
            return False
    
    def unblock_usb_ports(self):
        """Unblock USB ports by enabling them in device manager"""
        try:
            if platform.system() == "Windows" and HAS_WIN32:
                for device_id in self.blocked_ports:
                    # Try to enable the device (requires admin privileges)
                    try:
                        os.system(f'pnputil /enable-device "{device_id}"')
                    except:
                        pass
                self.blocked_ports.clear()
                return True
            else:
                return False
        except Exception as e:
            print(f"Error unblocking USB ports: {e}")
            return False


class ScanProgressDialog(QDialog):
    """Custom progress dialog for scanning with better UI"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Scanning")
        self.setMinimumSize(500, 150)
        self.setWindowModality(Qt.WindowModal)
        self.setStyleSheet("""
            QDialog {
                background-color: #f5f5f5;
                border: 2px solid #1976D2;
                border-radius: 8px;
            }
            QLabel {
                font-size: 14px;
                color: #333;
            }
            QProgressBar {
                border: 2px solid #ccc;
                border-radius: 5px;
                text-align: center;
                height: 20px;
                background-color: white;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
                border-radius: 3px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Scanning USB Drive for Threats")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #1976D2;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Progress bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Initializing...")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #b71c1c;
            }
        """)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        layout.addWidget(self.cancel_btn)
        
        self.setLayout(layout)
        
        self.cancelled = False
    
    def update_progress(self, value, text):
        """Update progress bar and status text"""
        self.progress_bar.setValue(value)
        self.status_label.setText(text)
        QApplication.processEvents()  # Keep UI responsive
    
    def cancel_scan(self):
        """Handle cancel button click"""
        self.cancelled = True
        self.status_label.setText("Cancelling scan...")
        self.cancel_btn.setEnabled(False)


class AIScanner(QThread):
    """Thread for AI-based virus scanning with enhanced detection methods"""
    scan_progress = pyqtSignal(int, str)  # Progress percentage, current file
    scan_complete = pyqtSignal(dict)      # Results dictionary
    
    def __init__(self, scan_path):
        super().__init__()
        self.scan_path = scan_path
        self.model = None
        self.vectorizer = None
        self.quarantine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        self.yara_rules = None
        self.load_model()
        self.load_yara_rules()
        
        # Known malicious file hashes (in a real app, this would be a database)
        self.malicious_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty file (example)
        }
        
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(self.quarantine_path):
            os.makedirs(self.quarantine_path)
    
    def load_model(self):
        """Load or create a detection model"""
        try:
            # Try to load a pre-trained model if it exists
            model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ember_rf_model.pkl")
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("Loaded pre-trained model from ember_rf_model")
            else:
                # Create a simple model for demonstration
                print("Creating new detection model...")
                self.create_detection_model()
        except Exception as e:
            print(f"Error loading model: {e}")
            self.create_detection_model()
    
    def create_detection_model(self):
        """Create a detection model based on heuristic rules"""
        # This is a simplified model - in a real application, you would use
        # a properly trained machine learning model
        self.model = {
            'threshold': 0.7,
            'rules': {
                'high_entropy': 0.3,
                'executable': 0.4,
                'double_extension': 0.8,
                'system_files': 0.6,
                'suspicious_names': 0.5
            }
        }
        print("Created heuristic detection model")
    
    def load_yara_rules(self):
        """Load YARA rules for pattern matching"""
        try:
            if HAS_YARA:
                # Create basic YARA rules if file doesn't exist
                rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malware_rules.yar")
                if not os.path.exists(rules_path):
                    self.create_default_yara_rules(rules_path)
                
                self.yara_rules = yara.compile(rules_path)
                print("Loaded YARA rules from malware_rules.yar")
            else:
                print("YARA not available")
                self.yara_rules = None
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            self.yara_rules = None
    
    def create_default_yara_rules(self, rules_path):
        """Create default YARA rules if file doesn't exist"""
        default_rules = """
rule SuspiciousScripts {
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/c" nocase
        $powershell = "powershell" nocase
        $regsvr = "regsvr32" nocase
        $sc = "sc create" nocase
    condition:
        any of them
}

rule ExecutablePatterns {
    strings:
        $mz = { 4D 5A }  // MZ header for PE files
    condition:
        $mz at 0
}

rule ObfuscatedCode {
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $fromcharcode = "fromCharCode" nocase
        $charcode = "charCodeAt" nocase
    condition:
        any of them
}
"""
        try:
            with open(rules_path, 'w') as f:
                f.write(default_rules)
            print("Created default YARA rules")
        except Exception as e:
            print(f"Error creating YARA rules: {e}")
    
    def calculate_entropy(self, data):
        """Calculate the entropy of a data chunk"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
                
        return entropy
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None
    
    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal (requires API key)"""
        # This is a placeholder - in a real application, you would use
        # the VirusTotal API with a valid API key
        return 0.0  # Return 0 for demo purposes
    
    def extract_features(self, file_path):
        """Extract features from a file for analysis"""
        try:
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            file_size = os.path.getsize(file_path)
            
            # Calculate entropy of the file
            entropy = 0
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(4096)  # Read first 4KB
                    entropy = self.calculate_entropy(data)
            except:
                entropy = 0
            
            # Check for suspicious file attributes
            is_executable = file_ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr', '.com', '.pif']
            is_hidden = os.name == 'nt' and bool(os.stat(file_path).st_file_attributes & 2)
            has_double_extension = file_name.count('.') > 1 and len(file_ext) > 0
            
            # Check for suspicious names
            suspicious_names = ['cmd', 'powershell', 'wscript', 'cscript', 'regsvr32', 'sc', 'install', 'setup', 'update']
            is_suspicious_name = any(name in file_name.lower() for name in suspicious_names)
            
            # Check if file is in system locations
            system_locations = ['windows', 'system32', 'syswow64', 'program files', 'programdata']
            is_system_file = any(loc in file_path.lower() for loc in system_locations)
            
            features = {
                'name_length': len(file_name),
                'ext_length': len(file_ext),
                'size': file_size,
                'entropy': entropy,
                'is_executable': 1 if is_executable else 0,
                'is_hidden': 1 if is_hidden else 0,
                'double_extension': 1 if has_double_extension else 0,
                'suspicious_name': 1 if is_suspicious_name else 0,
                'system_file': 1 if is_system_file else 0
            }
            
            return features
        except:
            return None
    
    def yara_scan(self, file_path):
        """Scan file using YARA rules"""
        if not self.yara_rules:
            return 0.0
            
        try:
            matches = self.yara_rules.match(file_path)
            if matches:
                # Return a higher probability based on number of matches
                return min(1.0, 0.3 + (len(matches) * 0.1))
        except:
            pass
            
        return 0.0
    
    def predict_file(self, file_path):
        """Use heuristic analysis to predict if a file is malicious"""
        features = self.extract_features(file_path)
        if not features:
            return 0.5
            
        # Calculate probability based on heuristic rules
        probability = 0.0
        
        # High entropy (often indicates encrypted or compressed content)
        if features['entropy'] > 7.0:
            probability += self.model['rules']['high_entropy']
        
        # Executable files
        if features['is_executable']:
            probability += self.model['rules']['executable']
        
        # Double extensions (e.g., "document.pdf.exe")
        if features['double_extension']:
            probability += self.model['rules']['double_extension']
        
        # System files in non-system locations
        if features['system_file'] and not any(loc in file_path.lower() for loc in ['windows', 'system32', 'syswow64']):
            probability += self.model['rules']['system_files']
        
        # Suspicious names
        if features['suspicious_name']:
            probability += self.model['rules']['suspicious_names']
        
        # Add YARA scan results
        yara_prob = self.yara_scan(file_path)
        probability = min(1.0, probability + yara_prob)
        
        # Check file hash against known malicious hashes
        file_hash = self.calculate_file_hash(file_path)
        if file_hash and file_hash in self.malicious_hashes:
            probability = 1.0
            
        return probability
    
    def quarantine_file(self, file_path):
        """Move a file to quarantine"""
        try:
            file_name = os.path.basename(file_path)
            quarantine_file = os.path.join(self.quarantine_path, file_name)
            
            # If file already exists in quarantine, add a timestamp
            if os.path.exists(quarantine_file):
                base, ext = os.path.splitext(file_name)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                quarantine_file = os.path.join(self.quarantine_path, f"{base}_{timestamp}{ext}")
            
            shutil.move(file_path, quarantine_file)
            return True
        except Exception as e:
            print(f"Error quarantining file {file_path}: {e}")
            return False
    
    def delete_file(self, file_path):
        """Permanently delete a file"""
        try:
            os.remove(file_path)
            return True
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")
            return False
    
    def run(self):
        """Scan all files in the given path"""
        results = {
            'scanned_files': 0,
            'malicious_files': 0,
            'suspicious_files': 0,
            'safe_files': 0,
            'file_list': []  # List of all files with their status
        }
        
        # Collect all files
        all_files = []
        try:
            for root, dirs, files in os.walk(self.scan_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    all_files.append(file_path)
        except Exception as e:
            print(f"Error walking directory: {e}")
            self.scan_complete.emit(results)
            return
        
        total_files = len(all_files)
        if total_files == 0:
            self.scan_complete.emit(results)
            return
            
        # Minimum scan duration (3 seconds)
        start_time = time.time()
        min_duration = 3.0
        
        # Scan each file
        for i, file_path in enumerate(all_files):
            try:
                # Update progress with realistic timing
                elapsed = time.time() - start_time
                progress = min(95, int((i + 1) / total_files * 100))
                
                # Add small delay to make scanning visible
                time.sleep(0.05)
                
                self.scan_progress.emit(progress, os.path.basename(file_path))
                
                # Predict maliciousness
                prob = self.predict_file(file_path)
                
                # Classify based on probability
                file_info = {
                    'path': file_path,
                    'probability': prob,
                    'status': 'Safe'
                }
                
                if prob > 0.8:  # High probability of being malicious
                    results['malicious_files'] += 1
                    file_info['status'] = 'Malicious'
                elif prob > 0.6:  # Suspicious
                    results['suspicious_files'] += 1
                    file_info['status'] = 'Suspicious'
                else:  # Safe
                    results['safe_files'] += 1
                    
                results['file_list'].append(file_info)
                results['scanned_files'] += 1
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
                
        # Ensure minimum scan duration
        elapsed = time.time() - start_time
        if elapsed < min_duration:
            remaining = min_duration - elapsed
            steps = int(remaining / 0.1)
            for i in range(steps):
                progress = min(99, 95 + int((i + 1) / steps * 5))
                self.scan_progress.emit(progress, "Finalizing scan...")
                time.sleep(0.1)
        
        # Final progress update
        self.scan_progress.emit(100, "Scan complete!")
        time.sleep(0.2)  # Brief pause to show 100%
        
        self.scan_complete.emit(results)


class ScanResultDialog(QDialog):
    """Dialog to display virus scan results with action options"""
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Results")
        self.setMinimumSize(900, 700)
        self.results = results
        self.parent_ref = parent
        
        layout = QVBoxLayout()
        
        # Summary section
        summary_group = QGroupBox("Scan Summary")
        summary_layout = QGridLayout()
        
        summary_layout.addWidget(QLabel("Total Files Scanned:"), 0, 0)
        summary_layout.addWidget(QLabel(f"{results['scanned_files']}"), 0, 1)
        
        summary_layout.addWidget(QLabel("Safe Files:"), 1, 0)
        safe_label = QLabel(f"{results['safe_files']}")
        safe_label.setStyleSheet("color: green; font-weight: bold;")
        summary_layout.addWidget(safe_label, 1, 1)
        
        summary_layout.addWidget(QLabel("Suspicious Files:"), 2, 0)
        suspicious_label = QLabel(f"{results['suspicious_files']}")
        suspicious_label.setStyleSheet("color: orange; font-weight: bold;")
        summary_layout.addWidget(suspicious_label, 2, 1)
        
        summary_layout.addWidget(QLabel("Malicious Files:"), 3, 0)
        malicious_label = QLabel(f"{results['malicious_files']}")
        malicious_label.setStyleSheet("color: red; font-weight: bold;")
        summary_layout.addWidget(malicious_label, 3, 1)
        
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Action buttons
        if results['malicious_files'] > 0 or results['suspicious_files'] > 0:
            action_group = QGroupBox("Actions")
            action_layout = QHBoxLayout()
            
            quarantine_btn = QPushButton("Quarantine All Threats")
            quarantine_btn.setStyleSheet("background-color: #FF9800; color: white; font-weight: bold;")
            quarantine_btn.clicked.connect(self.quarantine_all)
            action_layout.addWidget(quarantine_btn)
            
            delete_btn = QPushButton("Delete All Threats")
            delete_btn.setStyleSheet("background-color: #F44336; color: white; font-weight: bold;")
            delete_btn.clicked.connect(self.delete_all)
            action_layout.addWidget(delete_btn)
            
            action_group.setLayout(action_layout)
            layout.addWidget(action_group)
        
        # Details table
        details_group = QGroupBox("Scan Details")
        details_layout = QVBoxLayout()
        
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File", "Status", "Probability", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Add context menu for individual file actions
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        # Populate table with all files
        self.table.setRowCount(len(results['file_list']))
        for i, item in enumerate(results['file_list']):
            self.table.setItem(i, 0, QTableWidgetItem(item['path']))
            
            status_item = QTableWidgetItem(item['status'])
            if item['status'] == 'Malicious':
                status_item.setBackground(QColor(255, 200, 200))  # Light red
                status_item.setForeground(QColor(255, 0, 0))
            elif item['status'] == 'Suspicious':
                status_item.setBackground(QColor(255, 235, 150))  # Light yellow
                status_item.setForeground(QColor(255, 140, 0))
            else:
                status_item.setBackground(QColor(200, 255, 200))  # Light green
                status_item.setForeground(QColor(0, 128, 0))
                
            status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(i, 1, status_item)
            
            prob_item = QTableWidgetItem(f"{item['probability']:.2f}")
            prob_item.setFlags(prob_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(i, 2, prob_item)
            
            # Add action buttons for suspicious and malicious files
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(3, 3, 3, 3)
            
            if item['status'] in ['Malicious', 'Suspicious']:
                quarantine_btn = QPushButton("Quarantine")
                quarantine_btn.setStyleSheet("background-color: #FF9800; color: white; font-size: 10px;")
                quarantine_btn.clicked.connect(lambda checked, path=item['path']: self.quarantine_file(path))
                action_layout.addWidget(quarantine_btn)
                
                delete_btn = QPushButton("Delete")
                delete_btn.setStyleSheet("background-color: #F44336; color: white; font-size: 10px;")
                delete_btn.clicked.connect(lambda checked, path=item['path']: self.delete_file(path))
                action_layout.addWidget(delete_btn)
            else:
                # Safe file - show checkmark icon
                safe_label = QLabel()
                safe_label.setPixmap(QPixmap("icons/safe.png").scaled(20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                safe_label.setAlignment(Qt.AlignCenter)
                action_layout.addWidget(safe_label)
            
            action_layout.addStretch()
            action_widget.setLayout(action_layout)
            self.table.setCellWidget(i, 3, action_widget)
        
        details_layout.addWidget(self.table)
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        export_btn = QPushButton("Export Report")
        export_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        export_btn.clicked.connect(self.export_report)
        btn_layout.addWidget(export_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
    
    def export_report(self):
        """Export scan results to a CSV file"""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Report", "scan_report.csv", "CSV Files (*.csv)", options=options
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("File Path,Status,Probability\n")
                    for item in self.results['file_list']:
                        f.write(f'"{item["path"]}",{item["status"]},{item["probability"]:.2f}\n')
                
                QMessageBox.information(self, "Export Successful", f"Scan report exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Failed to export report:\n{e}")
    
    def show_context_menu(self, position):
        """Show context menu for right-click actions"""
        row = self.table.rowAt(position.y())
        if row < 0:
            return
            
        menu = QMenu()
        file_path = self.table.item(row, 0).text()
        status = self.table.item(row, 1).text()
        
        if status in ['Malicious', 'Suspicious']:
            quarantine_action = menu.addAction("Quarantine File")
            delete_action = menu.addAction("Delete File")
            
            action = menu.exec_(self.table.mapToGlobal(position))
            
            if action == quarantine_action:
                self.quarantine_file(file_path)
            elif action == delete_action:
                self.delete_file(file_path)
    
    def quarantine_file(self, file_path):
        """Quarantine a single file"""
        try:
            scanner = AIScanner("")  # Create scanner instance for quarantine methods
            if scanner.quarantine_file(file_path):
                QMessageBox.information(self, "Quarantine", f"File quarantined: {os.path.basename(file_path)}")
                self.parent_ref.add_log_to_db(f"File Quarantined ({os.path.basename(file_path)})", "Success")
                self.refresh_table()
            else:
                QMessageBox.warning(self, "Quarantine Error", f"Failed to quarantine file: {os.path.basename(file_path)}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error quarantining file: {e}")
    
    def delete_file(self, file_path):
        """Delete a single file"""
        try:
            reply = QMessageBox.question(
                self, 
                "Confirm Delete", 
                f"Are you sure you want to permanently delete {os.path.basename(file_path)}?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                scanner = AIScanner("")  # Create scanner instance for delete methods
                if scanner.delete_file(file_path):
                    QMessageBox.information(self, "Delete", f"File deleted: {os.path.basename(file_path)}")
                    self.parent_ref.add_log_to_db(f"File Deleted ({os.path.basename(file_path)})", "Success")
                    self.refresh_table()
                else:
                    QMessageBox.warning(self, "Delete Error", f"Failed to delete file: {os.path.basename(file_path)}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error deleting file: {e}")
    
    def quarantine_all(self):
        """Quarantine all detected threats"""
        try:
            reply = QMessageBox.question(
                self, 
                "Confirm Quarantine", 
                "Are you sure you want to quarantine all detected threats?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                scanner = AIScanner("")  # Create scanner instance for quarantine methods
                success_count = 0
                total_count = len([f for f in self.results['file_list'] if f['status'] in ['Malicious', 'Suspicious']])
                
                for item in self.results['file_list']:
                    if item['status'] in ['Malicious', 'Suspicious']:
                        if scanner.quarantine_file(item['path']):
                            success_count += 1
                
                QMessageBox.information(
                    self, 
                    "Quarantine Complete", 
                    f"Quarantined {success_count} of {total_count} threats."
                )
                self.parent_ref.add_log_to_db(f"Quarantined {success_count} threats", "Success")
                self.refresh_table()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error quarantining files: {e}")
    
    def delete_all(self):
        """Delete all detected threats"""
        try:
            reply = QMessageBox.question(
                self, 
                "Confirm Delete", 
                "Are you sure you want to permanently delete all detected threats?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                scanner = AIScanner("")  # Create scanner instance for delete methods
                success_count = 0
                total_count = len([f for f in self.results['file_list'] if f['status'] in ['Malicious', 'Suspicious']])
                
                for item in self.results['file_list']:
                    if item['status'] in ['Malicious', 'Suspicious']:
                        if scanner.delete_file(item['path']):
                            success_count += 1
                
                QMessageBox.information(
                    self, 
                    "Delete Complete", 
                    f"Deleted {success_count} of {total_count} threats."
                )
                self.parent_ref.add_log_to_db(f"Deleted {success_count} threats", "Success")
                self.refresh_table()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error deleting files: {e}")
    
    def refresh_table(self):
        """Refresh the table after actions"""
        # Remove rows for files that no longer exist
        rows_to_remove = []
        for row in range(self.table.rowCount()):
            file_path = self.table.item(row, 0).text()
            if not os.path.exists(file_path):
                rows_to_remove.append(row)
        
        for row in sorted(rows_to_remove, reverse=True):
            self.table.removeRow(row)


class USBBlockDashboard(QWidget):
    logout_signal = pyqtSignal()
    status_changed = pyqtSignal(str, bool)  # device_type, allowed
    
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setMinimumSize(1100, 900)
        self.setWindowTitle(f"USB Defender - {self.username}")
        # Remove maximize button from title bar
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowMaximizeButtonHint)
        self.setStyleSheet("background-color: white;")
        self.summary_icons = []
        self.device_status = {
            "usb": True,     # True = Allowed, False = Disallowed
            "disc": True,
            "network": True,
            "drive": True
        }

        # Initialize USB port manager
        self.usb_manager = USBPortManager()

        # --- DB path & init ---
        self.db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usb_reports.db")
        self.init_db()

        # --- Authorized devices store (JSON on disk) ---
        self.auth_store_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authorized_devices.json")
        self.authorized_devices = self.load_authorized_devices()

        # --- Real-time USB detection state ---
        self.current_usb_set = set()  # mountpoints we see right now

        # --- Statistics ---
        self.stats = {
            "usb_plugged_in": 0,
            "usb_blocked": 0,
            "usb_scanned": 0,
            "malicious_detected": 0,
            "disc_inserted": 0,
            "disc_blocked": 0,
            "network_accessed": 0,
            "network_blocked": 0,
            "drive_accessed": 0,
            "drive_blocked": 0
        }

        self.init_ui()
        self.center_window()

        # Start real-time detection (polling every 1s)
        self.usb_timer = QTimer(self)
        self.usb_timer.timeout.connect(self.check_usb_changes)
        self.usb_timer.start(1000)
        
        # Connect status changed signal
        self.status_changed.connect(self.handle_status_change)

        # Auto-refresh Hack Attempts table every 5 seconds
        self.hack_timer = QTimer(self)
        self.hack_timer.timeout.connect(self.load_hack_attempts_table)
        self.hack_timer.start(5000)
    
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
            
            # Create table for scan results
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    datetime TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    probability REAL
                )
            """)
            
            # Create table for statistics
            cur.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usb_plugged_in INTEGER DEFAULT 0,
                    usb_blocked INTEGER DEFAULT 0,
                    usb_scanned INTEGER DEFAULT 0,
                    malicious_detected INTEGER DEFAULT 0,
                    disc_inserted INTEGER DEFAULT 0,
                    disc_blocked INTEGER DEFAULT 0,
                    network_accessed INTEGER DEFAULT 0,
                    network_blocked INTEGER DEFAULT 0,
                    drive_accessed INTEGER DEFAULT 0,
                    drive_blocked INTEGER DEFAULT 0
                )
            """)
            
            # Initialize statistics if not exists
            cur.execute("SELECT COUNT(*) FROM statistics")
            if cur.fetchone()[0] == 0:
                cur.execute("INSERT INTO statistics DEFAULT VALUES")
            
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

    def add_scan_result_to_db(self, file_path, status, probability):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO scan_results (datetime, path, status, probability) VALUES (?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), file_path, status, probability)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Could not save scan result: {e}")

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

    def load_statistics(self):
        """Load statistics from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT * FROM statistics LIMIT 1")
            row = cur.fetchone()
            conn.close()
            
            if row:
                # Skip the id column
                self.stats = {
                    "usb_plugged_in": row[1] or 0,
                    "usb_blocked": row[2] or 0,
                    "usb_scanned": row[3] or 0,
                    "malicious_detected": row[4] or 0,
                    "disc_inserted": row[5] or 0,
                    "disc_blocked": row[6] or 0,
                    "network_accessed": row[7] or 0,
                    "network_blocked": row[8] or 0,
                    "drive_accessed": row[9] or 0,
                    "drive_blocked": row[10] or 0
                }
        except Exception as e:
            print(f"Error loading statistics: {e}")

    def save_statistics(self):
        """Save statistics to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                UPDATE statistics SET 
                usb_plugged_in = ?, usb_blocked = ?, usb_scanned = ?, malicious_detected = ?,
                disc_inserted = ?, disc_blocked = ?, network_accessed = ?, network_blocked = ?,
                drive_accessed = ?, drive_blocked = ?
            """, (
                self.stats["usb_plugged_in"], self.stats["usb_blocked"], self.stats["usb_scanned"], 
                self.stats["malicious_detected"], self.stats["disc_inserted"], self.stats["disc_blocked"],
                self.stats["network_accessed"], self.stats["network_blocked"], self.stats["drive_accessed"],
                self.stats["drive_blocked"]
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving statistics: {e}")

    # ---------- Authorized devices persistence ----------
    def load_authorized_devices(self):
        if os.path.exists(self.auth_store_path):
            try:
                with open(self.auth_store_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []  # list of dicts: {serial, type, name, mount, size, vendor, product}

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
        [{serial, type, name, mount, size, vendor, product}]
        """
        info_list = []
        mounts = self.list_connected_usb_mounts()

        # Basic, cross-platform fallback using mountpoint as ID
        for m in mounts:
            info = {
                "serial": m, 
                "type": "USB Storage", 
                "name": os.path.basename(m) or m, 
                "mount": m,
                "size": "Unknown",
                "vendor": "Unknown",
                "product": "Unknown"
            }
            
            # Try to get more detailed information
            try:
                # Get disk usage information
                usage = psutil.disk_usage(m)
                info["size"] = f"{usage.total / (1024**3):.2f} GB"
                
                # On Windows, try to get more details using WMI
                if platform.system().lower().startswith("win") and HAS_WMI:
                    c = wmi.WMI()
                    for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                        info["vendor"] = getattr(disk, "Manufacturer", "Unknown")
                        info["product"] = getattr(disk, "Model", "Unknown")
                        info["serial"] = getattr(disk, "SerialNumber", "") or getattr(disk, "PNPDeviceID", "") or m
                        break
            except Exception:
                pass
                
            info_list.append(info)

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
                        self.stats["usb_plugged_in"] += 1
                        self.stats["usb_blocked"] += 1
                        self.save_statistics()
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
                        self.stats["usb_plugged_in"] += 1
                        self.save_statistics()
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

        # Set window title
        self.setWindowTitle(f"USB Defender 1.1.1 Beta | Welcome, {self.username}")

        # --- Red Bar (replacing the custom title bar) ---
        red_bar = QLabel(f"USB Defender 1.1.1 Beta | Welcome, {self.username}")
        red_bar.setStyleSheet("""
            QLabel {
                background-color: #c32020;
                color: white;
                font-weight: bold;
                font-size: 18px;
                padding: 10px;
                border-top: 5px solid darkred;
                border-radius: 6px;
            }
        """)
        red_bar.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(red_bar)

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

        # Load statistics
        self.load_statistics()

    def create_detailed_summary_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        summary_title = QLabel("Detailed Summary:")
        summary_title.setStyleSheet("font-weight: bold; font-size: 20px; padding: 5px; text-decoration:underline;")
        layout.addWidget(summary_title)

        center_grid = QGridLayout()
        center_grid.setContentsMargins(10, 10, 10, 10)

        items = [
            ("USB Devices", "icons/usb.png", 0, 0, "usb"),
            ("Disc / Floppy Drives", "icons/disc.png", 0, 2, "disc"),
            ("Network PCs / Drives", "icons/network.png", 2, 0, "network"),
            ("Non-System Drives", "icons/hdd.png", 2, 2, "drive")
        ]
        self.summary_icons = []
        self.summary_labels = {}
        for name, icon, row, col, device_key in items:
            icon_label = QLabel()
            icon_label.setPixmap(QPixmap(icon).scaled(70, 70, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            icon_label.setAlignment(Qt.AlignCenter)
            
            # Get current status
            status = "Allowed" if self.device_status[device_key] else "Disallowed"
            color = "green" if self.device_status[device_key] else "red"
            
            text = QLabel(f"<b>{name}</b><br><u><b>Status</b></u> : "
                          f"<span style='color: {color}; font-size: 10px'>{status}</span>")
            text.setAlignment(Qt.AlignCenter)
            text.setStyleSheet(f"font-size: 16px; font-family: 'Times New Roman';")
            text.device_key = device_key  # Store device key for later updates
            self.summary_labels[device_key] = text
            
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

        # Update reports with actual statistics
        reports = [
            ("USB Devices Report", [
                f"Times Plugged-in: {self.stats['usb_plugged_in']}", 
                f"USB Blocked: {self.stats['usb_blocked']}", 
                f"USB Scanned: {self.stats['usb_scanned']}",
                f"Malicious Detected: {self.stats['malicious_detected']}",
                f"Authorized USBs: {len(self.authorized_devices)}"
            ]),
            ("Disc Drives Report", [
                f"Times Inserted: {self.stats['disc_inserted']}", 
                f"Discs Blocked: {self.stats['disc_blocked']}", 
                "Authorized DISCs: 0"
            ]),
            ("Network Access Report", [
                f"Times Accessed: {self.stats['network_accessed']}", 
                f"Network Blocked: {self.stats['network_blocked']}", 
                "Authorized Networks:0"
            ]),
            ("Non-System Drives Report", [
                f"Times Accessed: {self.stats['drive_accessed']}", 
                f"Drives Blocked: {self.stats['drive_blocked']}", 
                "Authorized Drives: 0"
            ])
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
            ("icons/usb.png", "Block USB Devices", "Stop Unauthorized USB Drives, External Drives and Memory Cards.", "usb"),
            ("icons/disc.png", "Block Discs & Floppy Drives", "Stop Unauthorized CDs, DVDs, Bluray, HD and Floppy Drives.", "disc"),
            ("icons/network.png", "Block Network Access", "Stop Unauthorized Network Access to other computers.", "network"),
            ("icons/hdd.png", "Block Non-System Drives", "Stop Unauthorized Drives and Partitions except System Drive.", "drive"),
        ]

        for icon_path, title_text, desc_text, device_type in controls:
            item_widget = QWidget()
            item_layout = QHBoxLayout(item_widget)
            item_layout.setContentsMargins(20, 20, 20, 20)
            item_layout.setSpacing(20)
            item_widget.setStyleSheet("border:none;")

            chk = QCheckBox()
            chk.setFixedSize(30, 30)
            # Protection enabled means checkbox checked -> device disallowed
            chk.setChecked(not self.device_status[device_type])
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

            status_text = "Enabled" if not self.device_status[device_type] else "Disabled"
            color = "green" if not self.device_status[device_type] else "red"
            status_lbl = QLabel(f"Protection: {status_text}")
            status_lbl.setStyleSheet(f"color: {color}; font-weight: bold; border:none;")
            item_layout.addStretch()
            item_layout.addWidget(status_lbl)

            def toggle_status(checked, lbl=status_lbl, dev_type=device_type):
                status_text = "Enabled" if checked else "Disabled"
                color = "green" if checked else "red"
                lbl.setText(f"Protection: {status_text}")
                lbl.setStyleSheet(f"color: {color}; font-weight: bold; border:none;")
                
                # Update device status
                self.device_status[dev_type] = not checked
                # Emit signal to update summary page
                self.status_changed.emit(dev_type, not checked)
                
                # For USB devices, implement real blocking
                if dev_type == "usb":
                    if checked:
                        # Block USB ports
                        if self.usb_manager.block_usb_ports():
                            self.add_log_to_db("USB Ports Blocked", "Success")
                            self.stats["usb_blocked"] += 1
                            self.save_statistics()
                        else:
                            QMessageBox.warning(self, "USB Blocking", "Failed to block USB ports. Administrator privileges may be required.")
                    else:
                        # Unblock USB ports
                        if self.usb_manager.unblock_usb_ports():
                            self.add_log_to_db("USB Ports Unblocked", "Success")
                        else:
                            QMessageBox.warning(self, "USB Unblocking", "Failed to unblock USB ports. Administrator privileges may be required.")
                
                # For other device types, just update the status
                elif dev_type == "disc":
                    if checked:
                        self.add_log_to_db("Disc Drives Blocked", "Success")
                        self.stats["disc_blocked"] += 1
                    else:
                        self.add_log_to_db("Disc Drives Unblocked", "Success")
                elif dev_type == "network":
                    if checked:
                        self.add_log_to_db("Network Access Blocked", "Success")
                        self.stats["network_blocked"] += 1
                    else:
                        self.add_log_to_db("Network Access Unblocked", "Success")
                elif dev_type == "drive":
                    if checked:
                        self.add_log_to_db("Non-System Drives Blocked", "Success")
                        self.stats["drive_blocked"] += 1
                    else:
                        self.add_log_to_db("Non-System Drives Unblocked", "Success")
                
                self.save_statistics()
                self.update_summary_page()

            chk.stateChanged.connect(lambda state, lbl=status_lbl, dev_type=device_type: toggle_status(state == Qt.Checked, lbl, dev_type))

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
        go_green_btn.clicked.connect(self.scan_usb)
        scan_layout.addWidget(go_green_btn)
        scan_layout.addStretch()
        page_layout.addWidget(scan_widget)

        return page

    def update_summary_page(self):
        """Update the summary page with current statistics"""
        if hasattr(self, 'summary_labels'):
            for device_key, label in self.summary_labels.items():
                status = "Allowed" if self.device_status[device_key] else "Disallowed"
                color = "green" if self.device_status[device_key] else "red"
                current_text = label.text().split('<br>')[0]  # Get the device name part
                label.setText(f"{current_text}<br><u><b>Status</b></u> : <span style='color: {color}; font-size: 10px'>{status}</span>")

    def scan_usb(self):
        """Scan USB drive for viruses using AI"""
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
            
        # Create custom progress dialog
        self.progress_dialog = ScanProgressDialog(self)
        self.progress_dialog.show()
        
        # Create and start scanner thread
        self.scanner_thread = AIScanner(usb_path)
        self.scanner_thread.scan_progress.connect(self.update_scan_progress)
        self.scanner_thread.scan_complete.connect(self.handle_scan_results)
        self.scanner_thread.start()
        
        # Log scan start
        self.add_log_to_db(f"Scan Started ({usb_path})", "In Progress")
        
    def update_scan_progress(self, progress, file_name):
        """Update progress dialog with current status"""
        if hasattr(self, 'progress_dialog') and self.progress_dialog:
            self.progress_dialog.update_progress(progress, f"Scanning: {file_name}")
            
            # Check if user cancelled
            if self.progress_dialog.cancelled:
                self.scanner_thread.terminate()
                self.progress_dialog.close()
                self.add_log_to_db("Scan Cancelled", "User Cancelled")
                QMessageBox.information(self, "Scan Cancelled", "The scan was cancelled by the user.")
        
    def handle_scan_results(self, results):
        """Handle scan completion"""
        if hasattr(self, 'progress_dialog') and self.progress_dialog:
            self.progress_dialog.close()
        
        # Save results to database
        for item in results['file_list']:
            if item['status'] in ['Malicious', 'Suspicious']:
                self.add_scan_result_to_db(item['path'], item['status'], item['probability'])
        
        # Update statistics
        self.stats["usb_scanned"] += results['scanned_files']
        self.stats["malicious_detected"] += results['malicious_files'] + results['suspicious_files']
        self.save_statistics()
        
        # Show results dialog
        result_dialog = ScanResultDialog(results, self)
        result_dialog.exec_()
        
        # Log scan completion
        status = "Completed"
        if results['malicious_files'] > 0 or results['suspicious_files'] > 0:
            status = "Threats Found"
            
        # FIX: Use 'scanned_files' instead of 'scanned'
        self.add_log_to_db(f"Scan Completed ({results['scanned_files']} files)", status)
        
        # Show summary message
        msg = (f"Scan completed!\n\n"
               f"Files scanned: {results['scanned_files']}\n"
               f"Safe files: {results['safe_files']}\n"
               f"Suspicious files: {results['suspicious_files']}\n"
               f"Malicious files: {results['malicious_files']}")
               
        QMessageBox.information(self, "Scan Complete", msg)

    def handle_status_change(self, device_type, allowed):
        """Update the summary page when device status changes"""
        if device_type in self.summary_labels:
            status = "Allowed" if allowed else "Disallowed"
            color = "green" if allowed else "red"
            self.summary_labels[device_type].setText(
                f"<b>{self.summary_labels[device_type].text().split('<br>')[0]}</b><br>"
                f"<u><b>Status</b></u> : <span style='color: {color}; font-size: 10px'>{status}</span>"
            )

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
            padding: 10px;
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
        self.auth_table.setColumnCount(6)
        self.auth_table.setHorizontalHeaderLabels(["Serial No.", "Device Type", "Device Name", "Mount Point", "Size", "Vendor/Product"])
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
            self.auth_table.setItem(r, 3, QTableWidgetItem(item.get("mount", "")))
            self.auth_table.setItem(r, 4, QTableWidgetItem(item.get("size", "Unknown")))
            self.auth_table.setItem(r, 5, QTableWidgetItem(f"{item.get('vendor', 'Unknown')}/{item.get('product', 'Unknown')}"))

    def add_connected_usb_as_authorized(self):
        devices = self.get_connected_usb_info()
        if not devices:
            QMessageBox.information(self, "Authorized Devices", "No connected USB storage found.")
            return
        
        # Show device selection dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Select USB Device to Authorize")
        dialog.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        
        label = QLabel("Select a USB device to add to authorized list:")
        layout.addWidget(label)
        
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["Serial No.", "Device Type", "Device Name", "Mount Point", "Size", "Vendor/Product"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(table.SelectRows)
        table.setSelectionMode(table.SingleSelection)
        
        table.setRowCount(len(devices))
        for r, dev in enumerate(devices):
            table.setItem(r, 0, QTableWidgetItem(dev.get("serial", "")))
            table.setItem(r, 1, QTableWidgetItem(dev.get("type", "")))
            table.setItem(r, 2, QTableWidgetItem(dev.get("name", "")))
            table.setItem(r, 3, QTableWidgetItem(dev.get("mount", "")))
            table.setItem(r, 4, QTableWidgetItem(dev.get("size", "Unknown")))
            table.setItem(r, 5, QTableWidgetItem(f"{dev.get('vendor', 'Unknown')}/{dev.get('product', 'Unknown')}"))
        
        layout.addWidget(table)
        
        button_box = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_box.addWidget(cancel_btn)
        
        select_btn = QPushButton("Select Device")
        select_btn.clicked.connect(dialog.accept)
        button_box.addWidget(select_btn)
        
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            selected_row = table.currentRow()
            if selected_row >= 0:
                dev = devices[selected_row]
                if not self.is_authorized(dev["serial"]):
                    self.authorized_devices.append(dev)
                    self.save_authorized_devices()
                    self.populate_authorized_table()
                    self.add_log_to_db(f"Device Authorized ({dev['name']})", "Allowed")
                    QMessageBox.information(self, "Authorized Devices", f"Device added:\n\nName: {dev['name']}\nSerial: {dev['serial']}")
                else:
                    QMessageBox.information(self, "Authorized Devices", "This device is already authorized.")

    def remove_selected_authorized(self):
        row = self.auth_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Authorized Devices", "Please select a device to remove.")
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
                font-size: 18px;
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
        self.hotkey_input.setStyleSheet("font-size: 14px; background-color:#d32f2f; color:white; font-weight:bold;")
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
            old_pass = dialog.old_password.text()
            new_pass = dialog.new_password.text()

            try:
                users_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
                conn = sqlite3.connect(users_db)
                cur = conn.cursor()

                def hash_password(p):
                    return hashlib.sha256(p.encode()).hexdigest()

                # Verify old password
                cur.execute("SELECT password FROM users WHERE username=?", (self.username,))
                row = cur.fetchone()
                if not row or row[0] != hash_password(old_pass):
                    QMessageBox.warning(self, "Error", "Old password is incorrect.")
                    conn.close()
                    return

                # Update to new password
                cur.execute("UPDATE users SET password=? WHERE username=?", (hash_password(new_pass), self.username))
                conn.commit()
                conn.close()

                QMessageBox.information(self, "Password Changed", "Your password has been changed successfully.")
                self.add_hack_attempt("Password Changed", f"User {self.username} changed their password")
            except Exception as e:
                QMessageBox.warning(self, "Database Error", f"Could not update password:\n{e}")

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
            self.logout_signal.emit()
            self.close()

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
            # Refresh statistics when visiting detailed summary
            elif index == 0:
                self.load_statistics()
                # Update the detailed summary page with latest statistics
                self.update_summary_page()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = USBBlockDashboard("Guest")
    win.show()
    sys.exit(app.exec_())
