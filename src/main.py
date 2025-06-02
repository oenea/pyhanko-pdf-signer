"""@package docstring
Documentation for main module.

More details.
"""
import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, 
                            QCheckBox, QTextEdit, QGroupBox, QFormLayout, QSpinBox,
                            QListWidget, QListWidgetItem, QMessageBox, QRadioButton, QButtonGroup)
from PyQt5.QtCore import Qt, QTimer

import click
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12, load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature, KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.keys import load_cert_from_pemder

selected_directory = ""


class FileSelectionWidget(QWidget):
    """File Selection Widget class."""

    def __init__(self, label_text, file_filter="All Files (*)", allow_multiple=False):
        """Constructor of File Selection Widget class.

        Default allow select one file, without extension contrains.
        """

        super().__init__()
        self.allow_multiple = allow_multiple
        self.file_paths = []
        
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.label = QLabel(label_text)
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_files)
        
        layout.addWidget(self.label)
        layout.addWidget(self.path_edit, 1)
        layout.addWidget(self.browse_button)
        
        self.setLayout(layout)
        self.file_filter = file_filter
    
    def browse_files(self):
        """Opens file dialog and allow select files."""

        if self.allow_multiple:
            file_paths, _ = QFileDialog.getOpenFileNames(
                self, "Select Files", "", self.file_filter
            )
            if file_paths:
                self.file_paths = file_paths
                self.path_edit.setText(f"{len(file_paths)} files selected")
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select File", "", self.file_filter
            )
            if file_path:
                self.file_paths = [file_path]
                self.path_edit.setText(file_path)
    
    def get_paths(self):
        """Get multiple paths."""

        return self.file_paths
    
    def get_path(self):
        """Get one path."""

        return self.file_paths[0] if self.file_paths else None


class DirectorySelectionWidget(QWidget):
    """Directory selection widget class."""

    def __init__(self, label_text, default_dir="."):
        """Initialize directory selection widget class."""

        super().__init__()
        
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.label = QLabel(label_text)
        self.path_edit = QLineEdit(default_dir)
        
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_directory)
        
        layout.addWidget(self.label)
        layout.addWidget(self.path_edit, 1)
        layout.addWidget(self.browse_button)
        
        self.setLayout(layout)
    
    def browse_directory(self):
        """Browse directory."""

        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory", self.path_edit.text()
        )
        if directory:
            self.path_edit.setText(directory)

            selected_directory = directory
            with open("last-key-path.txt", "w") as file:
                file.write(f"{directory}\n")
    
    def get_path(self):
        """Get path."""

        return self.path_edit.text()


class CertificateGenerationTab(QWidget):
    """Certificate generation tab."""

    def __init__(self):
        """"""

        super().__init__()
        self.initUI()
        
    def initUI(self):
        """Initialization of certificate generation tab."""

        layout = QVBoxLayout()

        chain_group = QGroupBox("Certificate Generation:")
        chain_form = QFormLayout(self)
        self.form_container_widget = QWidget()
        self.form_container_widget.setLayout(chain_form)
        
        self.passphrase_checkbox = QCheckBox("Encrypt private keys with passphrase", self)
        self.passphrase_checkbox.setChecked(True)
        self.passphrase_mode_label = QLabel("Select passphrase method:")
        chain_form.addRow(self.passphrase_checkbox)
        chain_form.addRow(self.passphrase_mode_label)

        self.passphrase_radio_btn_group = QButtonGroup(self)
        self.manual_passphrase_radio_btn = QRadioButton("Enter passphrase manually")
        self.generate_passphrase_radio_btn = QRadioButton("Generate new passphrase")

        self.passphrase_radio_btn_group.addButton(self.manual_passphrase_radio_btn, 1)
        self.passphrase_radio_btn_group.addButton(self.generate_passphrase_radio_btn, 2)
        
        self.certificate_type_label = QLabel("Select certificate type:")
        self.certificate_radio_btn_group = QButtonGroup(self)

        self.self_signed_certificate_radio_btn = QRadioButton("self-signed certificate")
        self.ca_signed_certificate_radio_btn = QRadioButton("CA-signed certificate")
        self.certificate_radio_btn_group.addButton(self.self_signed_certificate_radio_btn, 1)
        self.certificate_radio_btn_group.addButton(self.ca_signed_certificate_radio_btn, 2)
        
        self.passphrase_label = QLabel("Passphrase:")
        self.passphrase_input = QLineEdit(self)
        self.passphrase_input.setPlaceholderText("Enter passphrase (optional)")
        self.passphrase_input.setEchoMode(QLineEdit.Password)
       
        self.toggle_passphrase_visibility_btn = QPushButton("Show passphrase", self)
        self.toggle_passphrase_visibility_btn.setCheckable(True)
        self.toggle_passphrase_visibility_btn.clicked.connect(self.toggle_passphrase_visibility)

        with open("last-key-path.txt", "r") as file:
            selected_directory = file.readline().strip()
                
        self.output_dir = DirectorySelectionWidget("Output Directory:", selected_directory)
        
        self.org_name = QLineEdit("Contoso Corporation")
        self.org_name.setPlaceholderText("Your organization name")
        
        self.common_name = QLineEdit("John Rogovsky")
        self.common_name.setPlaceholderText("Your name")

        self.email_address = QLineEdit("john.rogovsky@contoso.com")
        self.email_address.setPlaceholderText("Your email")

        self.country_name = QLineEdit("US")
        self.country_name.setPlaceholderText("Country name")

        self.generate_passphrase_btn = QPushButton("Auto-generate passphrase")
        self.generate_passphrase_btn.clicked.connect(self.generate_random_passphrase)

        self.copy_passphrase_btn = QPushButton("Copy to Clipboard")
        self.copy_passphrase_btn.setEnabled(False)
        self.copy_passphrase_btn.clicked.connect(self.copy_passphrase_to_clipboard)        
        self.generate_chain_button = QPushButton("Generate Certificate(s)")

        self.generate_chain_button.clicked.connect(
            lambda checked: self.generate_cert(self.self_signed_certificate_radio_btn.isChecked())
        )
        
        chain_form.addWidget(self.passphrase_input)
        chain_form.addWidget(self.manual_passphrase_radio_btn)
        chain_form.addWidget(self.generate_passphrase_radio_btn)
        
        chain_form.addRow(self.passphrase_label)
        chain_form.addRow(self.generate_passphrase_btn)
        chain_form.addRow(self.toggle_passphrase_visibility_btn)
        chain_form.addRow(self.copy_passphrase_btn)
        
        chain_form.addRow(self.certificate_type_label)
        chain_form.addWidget(self.self_signed_certificate_radio_btn)
        chain_form.addWidget(self.ca_signed_certificate_radio_btn)
        chain_form.addRow(self.output_dir)
        chain_form.addRow("Your name:", self.common_name)
        chain_form.addRow("Organization Name:", self.org_name)
        chain_form.addRow("Email address:", self.email_address)
        chain_form.addRow("Coutry name:", self.country_name)

        chain_form.addRow(self.generate_chain_button)
        chain_group.setLayout(chain_form)
        
        console_group = QGroupBox("Log output:")
        console_layout = QVBoxLayout()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        console_group.setLayout(console_layout)
        
        layout.addWidget(chain_group)
        layout.addWidget(console_group)
        self.manual_passphrase_radio_btn.toggled.connect(self.manual_passphrase_mode)
        self.generate_passphrase_radio_btn.toggled.connect(self.generate_passphrase_mode)
        
        self.manual_passphrase_radio_btn.setChecked(True)
        self.self_signed_certificate_radio_btn.setChecked(True)
        
        passphrase_components = [
            self.toggle_passphrase_visibility_btn,
            self.copy_passphrase_btn,
            self.passphrase_mode_label,
            self.manual_passphrase_radio_btn, 
            self.generate_passphrase_radio_btn,
            self.generate_passphrase_btn, 
            self.passphrase_label,
            self.passphrase_input
        ]
        self.passphrase_checkbox.toggled.connect(
            lambda checked: self.toggle_elements_visibility(passphrase_components)
        )
        
        self.setLayout(layout)
   
    def toggle_elements_visibility(self, elements_to_toggle):
        """Toggle visibility of selected elements."""

        new_visibility_state = not elements_to_toggle[0].isVisible()
        for element in elements_to_toggle:
            element.setVisible(new_visibility_state)

    def log(self, message):
        """Log helper, send to message process and process Qt event."""

        self.console.append(message)
        QApplication.processEvents()

    def generate_random_passphrase(self):
        """Generate pseudorandom 4-digit passphrase."""

        import secrets
        passphrase = 0
        while (passphrase < 1000):
            passphrase = secrets.randbelow(10000)

        self.passphrase_input.setText(str(passphrase))
        self.copy_passphrase_btn.setEnabled(True)

    def copy_passphrase_to_clipboard(self):
        """Copy passphrase to clipboard."""

        clipboard = QApplication.clipboard()
        clipboard.setText(self.passphrase_input.text())
        self.log("Passphrase copied to clipboard.")

    def toggle_passphrase_visibility(self):
        """Toggle passphrase visiblity."""

        if self.toggle_passphrase_visibility_btn.isChecked():
            self.passphrase_input.setEchoMode(QLineEdit.Normal)
            self.toggle_passphrase_visibility_btn.setText("Hide passphrase")
        else:
            self.passphrase_input.setEchoMode(QLineEdit.Password)
            self.toggle_passphrase_visibility_btn.setText("Show passphrase")
            
    def manual_passphrase_mode(self):
        """Update manual passphrase mode."""

        if self.manual_passphrase_radio_btn.isChecked():
            self.passphrase_input.setReadOnly(False)
            self.passphrase_input.setPlaceholderText("Enter your password here")
            self.passphrase_input.clear()
            self.passphrase_input.setFocus()
            self.log("Selected manual enter passphrase mode.")

            if self.toggle_passphrase_visibility_btn.isChecked():
                self.passphrase_input.setEchoMode(QLineEdit.Normal)
            else:
                self.passphrase_input.setEchoMode(QLineEdit.Password)
        
    def generate_passphrase_mode(self):
        """Update auto-generated passphrase mode."""

        if self.generate_passphrase_radio_btn.isChecked():
            self.generate_random_passphrase()
            self.log("Generated passphrase.")

            self.passphrase_input.setReadOnly(True)
            self.passphrase_input.setPlaceholderText("Password has been generated")
            if self.toggle_passphrase_visibility_btn.isChecked():
                self.passphrase_input.setEchoMode(QLineEdit.Normal)
            else:
                self.passphrase_input.setEchoMode(QLineEdit.Password)
        
    def generate_root_cert(self):
        """Generates Root CA certificate."""

        self.root_key = rsa.generate_private_key(
            public_exponent = self.public_exponent,
            key_size = self.key_size,
            backend=default_backend()
        )
        self.log("Root CA private key generated.")

        self.root_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name_txt),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org_name_txt),
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name_txt),
        ])

        self.root_cert = (x509.CertificateBuilder()
            .subject_name(self.root_name)
            .issuer_name(self.root_name)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()), critical=False)
            .sign(self.root_key, hashes.SHA256(), default_backend()))

        self.log("Root CA certificate generated.")
    
    def generate_interpediate_cert(self):
        """Generates intermediate CA certificate."""

        self.intermediate_key = rsa.generate_private_key(
            public_exponent=self.
            public_exponent,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.log("Intermediate CA private key generated.")
        
        self.intermediate_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name_txt),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org_name_txt),
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name_txt),
        ])
        
        self.intermediate_cert = (x509.CertificateBuilder()
            .subject_name(self.intermediate_name)
            .issuer_name(self.root_name)
            .public_key(self.intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()), critical=False)
            .sign(self.root_key, hashes.SHA256(), default_backend()))

        self.log("Intermediate CA certificate generated.")
                
    def generate_signer_cert(self, self_signed=False):
        """Generates signer certificate."""
        self.signer_key = rsa.generate_private_key(
            public_exponent=self.public_exponent,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.log("Signer private key generated.")
        self.log(f"self_signed = {self_signed}")
        
        self.signer_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name_txt),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org_name_txt),
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name_txt),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email_address_txt),
        ])

        if self_signed:
            self.intermediate_name = self.signer_name
            self.intermediate_key = self.signer_key
        
        self.signer_cert = (x509.CertificateBuilder()
            .subject_name(self.signer_name)
            # if intermediate_name does not exists is throw error, so it is initialized to null
            .issuer_name((self.intermediate_name, self.signer_name)[bool(self_signed)])
            .public_key(self.signer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=(True, False)[bool(self_signed)],
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=(False, True)[bool(self_signed)],
                crl_sign=False,
                encipher_only=False,
                decipher_only=False),
                critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.signer_key.public_key()), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((self.intermediate_key.public_key(), self.signer_key.public_key())[bool(self_signed)]), critical=True)
            .sign((self.intermediate_key, self.signer_key)[bool(self_signed)], hashes.SHA256(), default_backend()))

        self.log("Signer certificate generated.")

    def generate_cert(self, self_signed=True):
        """Generates all private keys, certificates."""

        self.public_exponent = 65537
        self.key_size = 4096

        try:
            if self.passphrase_checkbox.isChecked() and not self.passphrase_input.text():
                QMessageBox.warning(self, "Passphrase Required", 
                "Please enter a passphrase or uncheck encryption")
                return

            output_path = self.output_dir.get_path()
            self.org_name_txt = self.org_name.text()
            self.common_name_txt = self.common_name.text()
            self.email_address_txt = self.email_address.text()
            self.country_name_txt = self.country_name.text()
            
            self.console.clear()

            encryption = (
                # uses aes-256-cbc"
                # https://github.com/pyca/cryptography/blob/aece5b3d47282beed31f7119e273b65816a0cf93/src/cryptography/hazmat/backends/openssl/backend.py#L1781
                serialization.BestAvailableEncryption(
                    self.passphrase_input.text().encode()
                ) if self.passphrase_checkbox.isChecked() else serialization.NoEncryption()
            )
            
            if not self_signed:
                self.generate_root_cert()
                self.generate_interpediate_cert()
                
                os.makedirs(output_path, exist_ok=True)
                
                root_cert_path = os.path.join(output_path, f"{self.org_name_txt}_Root_CA.pem")
                root_key_path = os.path.join(output_path, f"{self.org_name_txt}_Root_CA.key")
                intermediate_cert_path = os.path.join(output_path, f"{self.org_name_txt}_Intermediate_CA.pem")
                intermediate_key_path = os.path.join(output_path, f"{self.org_name_txt}_Intermediate_CA.key")

                with open(root_cert_path, "wb") as f:
                    f.write(self.root_cert.public_bytes(serialization.Encoding.PEM))
                    self.log(f"Root CA certificate: {root_cert_path}.")

                with open(root_key_path, "wb") as f:
                    f.write(self.root_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                    self.log(f"Root CA private key: {root_key_path}.")
                
                with open(intermediate_cert_path, "wb") as f:
                    f.write(self.intermediate_cert.public_bytes(serialization.Encoding.PEM))
                    self.log(f"Intermediate CA certificate: {intermediate_cert_path}")
                
                with open(intermediate_key_path, "wb") as f:
                    f.write(self.intermediate_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                    self.log(f"Intermediate CA private key: {intermediate_key_path}")

            self.generate_signer_cert(self_signed)
            signer_cert_path = os.path.join(output_path, f"{self.org_name_txt}.pem")
            signer_key_path = os.path.join(output_path, f"{self.org_name_txt}.key")
                
            with open(signer_cert_path, "wb") as f:
                f.write(self.signer_cert.public_bytes(serialization.Encoding.PEM))
                self.log(f"Signer certificate: {signer_cert_path}")
            
            with open(signer_key_path, "wb") as f:
                f.write(self.signer_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                ))
                self.log(f"Signer certificate: {signer_key_path}")

        except Exception as e:
            self.log(f"Error generating keys: {str(e)}")
    
class PDFSigningTab(QWidget):
    """PDF signing tab."""

    def __init__(self):
        """"""

        super().__init__()
        self.initUI()
    
    def initUI(self):
        """"""

        layout = QVBoxLayout()
        
        file_group = QGroupBox("File Selection")
        file_form = QFormLayout()
        
        self.pdf_file = FileSelectionWidget("PDF File:", "PDF Files (*.pdf)")
        self.output_file = QLineEdit()
        
        file_form.addRow(self.pdf_file)
        file_form.addRow("Output File:", self.output_file)
        file_group.setLayout(file_form)
        
        cert_group = QGroupBox("Certificate Selection")
        cert_form = QFormLayout()
        
        self.key_file = FileSelectionWidget("Private Key:", "Key Files (*.pem *.key)")
        self.cert_file = FileSelectionWidget("Certificate:", "Certificate Files (*.pem *.crt *.cer)")

        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Enter passphrase (if key is encrypted)")
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        cert_form.addRow("Passphrase:", self.passphrase_input)

        ca_chain_layout = QVBoxLayout()
        ca_chain_header = QHBoxLayout()
        
        ca_chain_label = QLabel("CA Chain Certificates:")
        self.add_cert_button = QPushButton("Add")
        self.add_cert_button.clicked.connect(self.add_ca_cert)
        self.remove_cert_button = QPushButton("Remove")
        self.remove_cert_button.clicked.connect(self.remove_ca_cert)
        
        ca_chain_header.addWidget(ca_chain_label)
        ca_chain_header.addWidget(self.add_cert_button)
        ca_chain_header.addWidget(self.remove_cert_button)
        ca_chain_header.addStretch()
        
        self.ca_chain_list = QListWidget()
        
        ca_chain_layout.addLayout(ca_chain_header)
        ca_chain_layout.addWidget(self.ca_chain_list)
        
        cert_form.addRow(self.key_file)
        cert_form.addRow(self.cert_file)
        cert_form.addRow(ca_chain_layout)
        cert_group.setLayout(cert_form)
        
        sig_group = QGroupBox("Signature Options")
        sig_form = QFormLayout()
        
        self.field_name = QLineEdit("Signature1")
        self.create_field = QCheckBox("Create signature field if it does not exist")
        self.location = QLineEdit()
        self.contact_info = QLineEdit()
        
        sig_form.addRow("Field Name:", self.field_name)
        sig_form.addRow(self.create_field)
        sig_form.addRow("Location:", self.location)
        sig_form.addRow("Contact Info:", self.contact_info)
        sig_group.setLayout(sig_form)

        self.signature_image_path = FileSelectionWidget("Signature Image:", "Image Files (*.jpg *.png *.bmp)")
        sig_form.addRow(self.signature_image_path)

        self.timestamp_checkbox = QCheckBox("Add timestamp")
        sig_form.addRow(self.timestamp_checkbox)
        
        self.sign_button = QPushButton("Sign PDF")
        self.sign_button.clicked.connect(self.sign_pdf)
        
        console_group = QGroupBox("Output")
        console_layout = QVBoxLayout()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        console_group.setLayout(console_layout)
        
        layout.addWidget(file_group)
        layout.addWidget(cert_group)
        layout.addWidget(sig_group)
        layout.addWidget(self.sign_button)
        layout.addWidget(console_group)
        
        self.setLayout(layout)
    
    def add_ca_cert(self):
        """Add ca certificate."""

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select CA Certificate", "", "Certificate Files (*.pem *.crt *.cer)"
        )
        if file_path:
            item = QListWidgetItem(file_path)
            self.ca_chain_list.addItem(item)
    
    def remove_ca_cert(self):
        """Remove ca certificate."""

        selected_items = self.ca_chain_list.selectedItems()
        if selected_items:
            for item in selected_items:
                self.ca_chain_list.takeItem(self.ca_chain_list.row(item))
    
    def log(self, message):
        """Log to app console."""

        self.console.append(message)
        QApplication.processEvents()
    
    def sign_pdf(self):
        try:
            self.console.clear()
            
            if self.timestamp_checkbox.isChecked():
                signature_meta.timestamp_url = "http://timestamp.digicert.com"
                self.log("Adding timestamp to the signature.")

            pdf_paths = self.pdf_file.get_paths()
            if not pdf_paths:
                self.log("Error: Please select a PDF file to sign.")
                return
            
            pdf_file = pdf_paths[0]
            
            output_file = self.output_file.text()
            if not output_file:
                output_file = pdf_file.replace(".pdf", "_signed.pdf")
                self.output_file.setText(output_file)
            
            key_paths = self.key_file.get_paths()
            if not key_paths:
                self.log("Error: Please select a private key file.")
                return
            
            key_file = key_paths[0]
            
            cert_paths = self.cert_file.get_paths()
            if not cert_paths:
                self.log("Error: Please select a certificate file.")
                return
            
            cert_file = cert_paths[0]
            
            ca_chain = []
            for i in range(self.ca_chain_list.count()):
                ca_chain.append(self.ca_chain_list.item(i).text())
            
            field_name = self.field_name.text()
            create_field = self.create_field.isChecked()
            location = self.location.text()
            contact_info = self.contact_info.text()
            
            self.log(f"Signing PDF: {pdf_file}")
            self.log(f"Output file: {output_file}")
            self.log(f"Using key: {key_file}")
            self.log(f"Using certificate: {cert_file}")
            if ca_chain:
                self.log(f"Using CA chain: {', '.join(ca_chain)}")
            
            key_passphrase = self.passphrase_input.text().encode() if self.passphrase_input.text() else None
            self.log("Loading certificates and keys...")
            
            cms_signer = signers.SimpleSigner.load(
                key_file, cert_file,
                ca_chain_files=ca_chain,
                key_passphrase=key_passphrase
            )

            if key_passphrase:
                self.log("Using encrypted private key with passphrase.")

            self.log("Preparing PDF for signing...")
            with open(pdf_file, 'rb') as doc:
                w = IncrementalPdfFileWriter(doc)
                
                if create_field:
                    self.log("Creating signature field...")
                    fields.append_signature_field(
                        w, sig_field_spec=fields.SigFieldSpec(
                            sig_field_name=field_name, 
                            box=(100, 100, 300, 200)
                        )
                    )
                
                signature_meta = signers.PdfSignatureMetadata(
                    field_name=field_name,
                    signer_key_usage=["digital_signature", "non_repudiation"],
                    subfilter=fields.SigSeedSubFilter.PADES,
                )
                
                if location:
                    signature_meta.location = location
                if contact_info:
                    signature_meta.contact_info = contact_info
                
                self.log("Signing PDF...")
                with open(output_file, 'wb') as out:
                    signers.sign_pdf(
                        w,
                        signature_meta=signature_meta,
                        signer=cms_signer,
                        output=out
                    )
                
            self.log(f"PDF signed successfully. Output saved to: {output_file}")
            
        except Exception as e:
            self.log(f"Error signing PDF: {str(e)}")
            

class PDFVerificationTab(QWidget):
    """PDF verification tab."""

    def __init__(self):
        """Initialize PDF verification tab."""

        super().__init__()
        self.initUI()
    
    def initUI(self):
        """Initialize PDF verification tab."""

        layout = QVBoxLayout()
        
        file_group = QGroupBox("File Selection")
        file_form = QFormLayout()
        
        self.pdf_file = FileSelectionWidget("PDF File:", "PDF Files (*.pdf)")
        file_form.addRow(self.pdf_file)
        file_group.setLayout(file_form)
        
        cert_group = QGroupBox("Certificate Selection")
        cert_form = QFormLayout()
        
        self.trust_cert = FileSelectionWidget("Trust Root Certificate:", "Certificate Files (*.pem *.crt *.cer)")
        
        intermediate_layout = QVBoxLayout()
        intermediate_header = QHBoxLayout()
        
        intermediate_label = QLabel("Intermediate Certificates:")
        self.add_int_cert_button = QPushButton("Add")
        self.add_int_cert_button.clicked.connect(self.add_intermediate_cert)
        self.remove_int_cert_button = QPushButton("Remove")
        self.remove_int_cert_button.clicked.connect(self.remove_intermediate_cert)
        
        intermediate_header.addWidget(intermediate_label)
        intermediate_header.addWidget(self.add_int_cert_button)
        intermediate_header.addWidget(self.remove_int_cert_button)
        intermediate_header.addStretch()
        
        self.intermediate_list = QListWidget()
        
        intermediate_layout.addLayout(intermediate_header)
        intermediate_layout.addWidget(self.intermediate_list)
        
        cert_form.addRow(self.trust_cert)
        cert_form.addRow(intermediate_layout)
        cert_group.setLayout(cert_form)

        cert_legacy_group = QGroupBox("Legacy Certificate Selection")
        cert_legacy_form = QFormLayout()
        
        self.trust_legacy_cert = FileSelectionWidget("Legacy Certificate:", "Legacy Certificate Files (*.pem *.crt *.cer)")

        cert_legacy_form.addRow(self.trust_legacy_cert)
        cert_legacy_group.setLayout(cert_legacy_form)
        
        verify_group = QGroupBox("Verification Options")
        verify_form = QFormLayout()
        
        self.sig_index = QSpinBox()
        self.sig_index.setMinimum(-1)
        self.sig_index.setValue(-1)
        self.sig_index.setSpecialValueText("All signatures")
        
        verify_form.addRow("Signature Index:", self.sig_index)
        verify_group.setLayout(verify_form)
        
        self.verify_button = QPushButton("Verify PDF Signatures")
        self.verify_button.clicked.connect(self.verify_pdf)
        
        console_group = QGroupBox("Verification Results")
        console_layout = QVBoxLayout()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        console_group.setLayout(console_layout)
        
        layout.addWidget(file_group)
        layout.addWidget(cert_group)
        layout.addWidget(verify_group)
        layout.addWidget(self.verify_button)
        layout.addWidget(console_group)
        
        self.setLayout(layout)
    
    def add_intermediate_cert(self):
        """Add intermediate certificate."""

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Intermediate Certificate", "", "Certificate Files (*.pem *.crt *.cer)"
        )
        if file_path:
            item = QListWidgetItem(file_path)
            self.intermediate_list.addItem(item)
    
    def remove_intermediate_cert(self):
        """Remove intermediate certificate."""

        selected_items = self.intermediate_list.selectedItems()
        if selected_items:
            for item in selected_items:
                self.intermediate_list.takeItem(self.intermediate_list.row(item))
    
    def log(self, message):
        """Log to app console."""

        self.console.append(message)
        QApplication.processEvents()

    def format_hex(self, byte_string):
        """Format hexadecimal to decimal."""

        if byte_string is None:
            return "Not Present"
        if isinstance(byte_string, bytes):
            return byte_string.hex(':')
        return str(byte_string) 

    def format_general_names(self, general_names_obj):
        """Format general names."""

        if not general_names_obj:
            return "Not Present"
        
        names_list = []
        items_to_format = general_names_obj
        if not isinstance(general_names_obj, (list, tuple)):
            items_to_format = [general_names_obj]

        for gn in items_to_format:
            if hasattr(gn, 'name') and hasattr(gn, 'chosen_value'): 
                name_type = gn.name
                value = gn.chosen_value
                if hasattr(value, 'native'): 
                    value_str = str(value.native)
                else:
                    value_str = str(value)
                names_list.append(f"{name_type}: {value_str}")
            elif hasattr(gn, 'native'): 
                names_list.append(str(gn.native))
            else:
                names_list.append(str(gn))
                
        return "; ".join(names_list) if names_list else "Not Present"
    
    def verify_pdf(self):
        """Verify PDF if signature is valid."""

        try:
            self.console.clear()
            
            pdf_paths = self.pdf_file.get_paths()
            if not pdf_paths:
                self.log("Error: Please select a PDF file to verify.")
                return
            
            pdf_file = pdf_paths[0]
            
            trust_cert_paths = self.trust_cert.get_paths()
            if not trust_cert_paths:
                self.log("Error: Please select a trust root certificate.")
                return
            
            trust_cert = trust_cert_paths[0]
            
            other_certs = []
            for i in range(self.intermediate_list.count()):
                other_certs.append(self.intermediate_list.item(i).text())
            
            signature_index = self.sig_index.value()
            if signature_index == -1:
                signature_index = None
            
            self.log(f"Verifying PDF: {pdf_file}")
            self.log(f"Using trust root: {trust_cert}")
            if other_certs:
                self.log(f"Using intermediate certificates: {', '.join(other_certs)}")
            
            self.log("Loading certificates...")
            root_cert = load_cert_from_pemder(trust_cert)
            
            other_cert_objs = []
            for cert_path in other_certs:
                try:
                    cert = load_cert_from_pemder(cert_path)
                    other_cert_objs.append(cert)
                    self.log(f"Loaded intermediate certificate: {cert_path}")
                except Exception as e:
                    self.log(f"Warning: Failed to load certificate {cert_path}: {str(e)}")
            
            self.log("Creating validation context...")
            vc = ValidationContext(
                trust_roots=[root_cert],
                other_certs=other_cert_objs
            )
            
            key_usage_settings = KeyUsageConstraints(
                key_usage={'digital_signature', 'nonRepudiation'},
                match_all_key_usages=False
            )
            
            self.log("Opening PDF and validating signatures...")
            with open(pdf_file, 'rb') as doc:
                r = PdfFileReader(doc)
                sigs = r.embedded_signatures
                
                if not sigs:
                    self.log("No signatures found in the PDF.")
                    return
                    
                self.log(f"Found {len(sigs)} signatures in the PDF.")
                
                if signature_index is not None:
                    if signature_index < 0 or signature_index >= len(sigs):
                        self.log(f"Error: Signature index {signature_index} is out of range.")
                        return
                    sig_indices = [signature_index]
                else:
                    sig_indices = range(len(sigs))
                
                for idx in sig_indices:
                    sig = sigs[idx]
                    
                    try:
                        status = validate_pdf_signature(
                            embedded_sig=sig,
                            signer_validation_context=vc,
                            key_usage_settings=key_usage_settings
                        )

                        self.log(f"Verifying signature {idx}:")

                        aia_value_obj = sig.signer_cert.authority_information_access_value
                        if aia_value_obj:
                            self.log(f"  Authority Information Access (AIA):")
                            for access_description in aia_value_obj:
                                method_oid = access_description['access_method'].native
                                location = access_description['access_location']
                                location_type = location.name
                                location_value = location.chosen_value.native if hasattr(location.chosen_value, 'native') else location.chosen_value
                                self.log(f"    - Method: {method_oid}")
                                self.log(f"      Location ({location_type}): {location_value}")
                        else:
                            self.log(f"  Authority Information Access (AIA): Not Present")

                        ski_bytes = sig.signer_cert.key_identifier
                        self.log(f"  Subject Key Identifier (SKI): {self.format_hex(ski_bytes)}")

                        akid_value_obj = sig.signer_cert.authority_key_identifier_value
                        if akid_value_obj:
                            self.log(f"  Authority Key Identifier (AKI):")
                            native_akid = akid_value_obj.native
                            akid_key_id = native_akid.get('key_identifier')
                            self.log(f"    Key Identifier: {self.format_hex(akid_key_id)}")

                            akid_issuer = native_akid.get('authority_cert_issuer')
                            if akid_issuer:
                                issuers_str_list = []
                                for gn_dict in akid_issuer:
                                    if 'directory_name' in gn_dict:
                                        issuers_str_list.append(f"Directory Name (details omitted for brevity, see below)")
                                    else:
                                        issuers_str_list.append(f"{gn_dict.get('type', 'Unknown')}: {gn_dict.get('value', 'N/A')}")
                                self.log(f"    Authority Cert Issuer: {'; '.join(issuers_str_list) if issuers_str_list else 'Not Present'}")
                            else:
                                self.log(f"    Authority Cert Issuer: Not Present")

                            self.log(f"    Authority Cert Issuer & Serial (from cert direct attr): {sig.signer_cert.authority_issuer_serial or 'Not Present'}")

                            akid_serial = native_akid.get('authority_cert_serial_number')
                            self.log(f"    Authority Cert Serial Number: {akid_serial if akid_serial is not None else 'Not Present'}")
                        else:
                            self.log(f"  Authority Key Identifier (AKI): Not Present")

                        basic_constraints_obj = sig.signer_cert.basic_constraints_value
                        ca_status_direct = sig.signer_cert.ca
                        self.log(f"  Basic Constraints:")
                        self.log(f"    Is CA (direct attribute): {ca_status_direct}")
                        if basic_constraints_obj:
                            native_bc = basic_constraints_obj.native
                            is_ca_from_ext = native_bc.get('ca', False)
                            path_len = native_bc.get('path_len_constraint')
                            self.log(f"    Is CA (from extension): {is_ca_from_ext}")
                            self.log(f"    Path Length Constraint: {path_len if path_len is not None else 'Not Specified'}")
                        else:
                            self.log(f"    (Extension not present or could not be parsed)")


                        cert_policies_obj = sig.signer_cert.certificate_policies_value
                        if cert_policies_obj:
                            self.log(f"  Certificate Policies:")
                            if not cert_policies_obj.native: 
                                self.log(f"    No policies defined in extension.")
                            else:
                                for policy_info in cert_policies_obj.native: 
                                    oid = policy_info.get('policy_identifier', 'Unknown OID')
                                    qualifiers_text = ""
                                    if policy_info.get('policy_qualifiers'):
                                        qualifiers_text = f" (has {len(policy_info['policy_qualifiers'])} qualifier(s))"
                                    self.log(f"    - Policy OID: {oid}{qualifiers_text}")
                        else:
                            self.log(f"  Certificate Policies: Not Present (extension not present)")

                        if hasattr(status, 'signing_time') and status.signing_time:
                            self.log(f"  Signing time: {status.signing_time}")
                        
                        if status.bottom_line == 1:
                            self.log("  ✓ Signature verification successful")
                        else:
                            self.log(f"  ✗ Signature verification failed")
                            
                        if hasattr(status, 'modification_analysis'):
                            coverage = status.modification_analysis()
                            if coverage:
                                self.log(f"  Document coverage: {coverage.coverage_level}")
                                if not coverage.docmdp_ok:
                                    self.log("  ⚠ Document was modified in a way that violates the permissions set by the signer")
                        
                    except Exception as e:
                        self.log(f"  ✗ Signature validation failed: {str(e)}")
            
        except Exception as e:
            self.log(f"Error verifying PDF: {str(e)}")


class MainWindow(QMainWindow):
    """Main window of application."""

    def __init__(self):
        """Main window of application initializer."""

        super().__init__()
        self.initUI()
        self.startDirectoryChecker()
    
    def initUI(self):
        """Main window of application initializer."""
        
        self.setWindowTitle("PDF Signing Tool")
        self.setMinimumSize(800, 600)
        
        tabs = QTabWidget()
        
        tabs.addTab(CertificateGenerationTab(), "Generate Certificates")
        tabs.addTab(PDFSigningTab(), "Sign PDF")
        tabs.addTab(PDFVerificationTab(), "Verify PDF")
        
        self.setCentralWidget(tabs)

    def startDirectoryChecker(self):
        """Start timer for directory checker."""

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.checkDirectory)
        self.timer.start(1)
    
    def checkDirectory(self):
        """Check directory if exists."""

        if not os.path.exists(selected_directory):
            QMessageBox.warning(self, "Selected directory does not exists.", 
                "Please plug apropriate storage device or change private key directory.")

if __name__ == '__main__':
    with open("last-key-path.txt", "r") as file:
        selected_directory = file.readline().strip()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
