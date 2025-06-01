import sys
import secrets
import string
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QRadioButton, QLabel, QButtonGroup
)
from PyQt5.QtCore import Qt

class IntuitivePasswordWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Intuitive Password Setup")
        self.setGeometry(300, 300, 400, 200) # x, y, width, height

        main_layout = QVBoxLayout()

        # --- Mode Selection ---
        mode_label = QLabel("Choose password method:")
        main_layout.addWidget(mode_label)

        self.radio_button_group = QButtonGroup(self) # Manages exclusivity

        self.manual_radio = QRadioButton("Enter password manually")
        self.generate_radio = QRadioButton("Generate a new password")

        self.radio_button_group.addButton(self.manual_radio, 1) # Assign ID 1
        self.radio_button_group.addButton(self.generate_radio, 2) # Assign ID 2

        radio_layout = QHBoxLayout()
        radio_layout.addWidget(self.manual_radio)
        radio_layout.addWidget(self.generate_radio)
        main_layout.addLayout(radio_layout)

        # --- Password Field ---
        self.password_field = QLineEdit(self)
        self.password_field.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(self.password_field)

        # --- (Optional) Show/Hide Button for better UX ---
        self.toggle_visibility_button = QPushButton("Show Password", self)
        self.toggle_visibility_button.setCheckable(True) # Make it a toggle button
        self.toggle_visibility_button.clicked.connect(self.toggle_password_visibility)
        main_layout.addWidget(self.toggle_visibility_button)

        # --- Get Password Button (for demonstration) ---
        self.get_password_button = QPushButton("Get Password Value", self)
        self.get_password_button.clicked.connect(self.print_password)
        main_layout.addWidget(self.get_password_button)

        self.setLayout(main_layout)

        # --- Connect Signals ---
        # Using buttonToggled from QButtonGroup is cleaner than connecting each radio button
        self.radio_button_group.buttonToggled.connect(self.update_password_mode)

        # --- Initial State ---
        self.manual_radio.setChecked(True) # Default to manual entry
        self.update_password_mode(self.manual_radio, True) # Initialize UI based on default

    def update_password_mode(self, button, checked):
        if not checked: # Only act when a button becomes checked
            return

        selected_id = self.radio_button_group.id(button)

        if selected_id == 1: # Manual mode
            self.password_field.setReadOnly(False)
            self.password_field.setPlaceholderText("Enter your password here")
            self.password_field.clear() # Clear any generated password
            self.password_field.setFocus()
            print("Switched to: Manual Password Entry")
            # Ensure echo mode is password if it was changed
            if self.toggle_visibility_button.isChecked():
                 # If show is active, keep it normal, else password
                pass # Visibility managed by toggle_password_visibility
            else:
                self.password_field.setEchoMode(QLineEdit.Password)


        elif selected_id == 2: # Generate mode
            self.generate_and_set_password()
            self.password_field.setReadOnly(True) # Make it read-only
            self.password_field.setPlaceholderText("Password has been generated")
            print("Switched to: Generated Password")
            # Optionally show the generated password briefly or by default
            # For this example, we'll respect the current visibility toggle
            if not self.toggle_visibility_button.isChecked():
                self.password_field.setEchoMode(QLineEdit.Password)
            else:
                self.password_field.setEchoMode(QLineEdit.Normal)


    def generate_and_set_password(self):
        # Basic password generation (customize as needed for strength)
        length = 14
        characters = string.ascii_letters + string.digits + string.punctuation
        # Ensure at least one of each category for stronger passwords (example)
        password = (secrets.choice(string.ascii_lowercase) +
                    secrets.choice(string.ascii_uppercase) +
                    secrets.choice(string.digits) +
                    secrets.choice(string.punctuation))
        password += ''.join(secrets.choice(characters) for _ in range(length - len(password)))
        
        # Shuffle to make it less predictable
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        generated_password = ''.join(password_list)

        self.password_field.setText(generated_password)
        print(f"Generated Password: {generated_password}") # For demo purposes

    def toggle_password_visibility(self):
        if self.toggle_visibility_button.isChecked():
            self.password_field.setEchoMode(QLineEdit.Normal)
            self.toggle_visibility_button.setText("Hide Password")
        else:
            self.password_field.setEchoMode(QLineEdit.Password)
            self.toggle_visibility_button.setText("Show Password")

    def print_password(self):
        # This is just to demonstrate getting the value
        # In a real app, you'd use this value for login, saving, etc.
        current_password = self.password_field.text()
        print(f"Current password field value: {current_password}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = IntuitivePasswordWidget()
    window.show()
    sys.exit(app.exec_())
