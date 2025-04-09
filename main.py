import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, 
                            QCheckBox, QTextEdit, QGroupBox, QFormLayout, QSpinBox,
                            QListWidget, QListWidgetItem, QMessageBox)
from PyQt5.QtCore import Qt

import click
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import PrivateFormat, load_pem_private_key, pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature, KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.keys import load_cert_from_pemder

class FileSelectionWidget(QWidget):
    def __init__(self, label_text, file_filter="All Files (*)", allow_multiple=False):
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
        return self.file_paths
    
    def get_path(self):
        return self.file_paths[0] if self.file_paths else None


class DirectorySelectionWidget(QWidget):
    def __init__(self, label_text, default_dir="."):
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
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory", self.path_edit.text()
        )
        if directory:
            self.path_edit.setText(directory)
    
    def get_path(self):
        return self.path_edit.text()


class CertificateGenerationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()
        
        # Chain generation group
        chain_group = QGroupBox("Certificate Chain Generation")
        chain_form = QFormLayout()
        
        self.output_dir = DirectorySelectionWidget("Output Directory:", "./certs")
        self.org_name = QLineEdit("Your Organization")
        self.passphrase_check = QCheckBox("Encrypt private keys with passphrase")
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Enter passphrase (optional)")
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.generate_passphrase_btn = QPushButton("Generate")
        self.generate_passphrase_btn.clicked.connect(self.generate_random_passphrase)

        # Add this in CertificateGenerationTab.initUI() under the passphrase input field
        self.copy_passphrase_btn = QPushButton("Copy to Clipboard")
        self.copy_passphrase_btn.setEnabled(False)  # Initially disabled
        self.copy_passphrase_btn.clicked.connect(self.copy_passphrase_to_clipboard)

        chain_form.addRow(self.passphrase_check)
        chain_form.addRow("Passphrase:", self.passphrase_input)
        chain_form.addRow(self.generate_passphrase_btn)
        chain_form.addRow(self.copy_passphrase_btn)
        
        self.generate_chain_button = QPushButton("Generate Certificate Chain")
        self.generate_chain_button.clicked.connect(self.generate_chain)
        
        chain_form.addRow(self.output_dir)
        chain_form.addRow("Organization Name:", self.org_name)
        chain_form.addRow(self.generate_chain_button)
        chain_group.setLayout(chain_form)
        
        # Legacy key generation group
        legacy_group = QGroupBox("Legacy Self-Signed Certificate (Not Recommended)")
        legacy_form = QFormLayout()
        
        self.legacy_output_dir = DirectorySelectionWidget("Output Directory:", ".")
        self.generate_keys_button = QPushButton("Generate Self-Signed Certificate")
        self.generate_keys_button.clicked.connect(self.generate_keys)
        
        legacy_form.addRow(self.legacy_output_dir)
        legacy_form.addRow(self.generate_keys_button)
        legacy_group.setLayout(legacy_form)
        
        # Output console
        console_group = QGroupBox("Output")
        console_layout = QVBoxLayout()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        console_group.setLayout(console_layout)
        
        layout.addWidget(chain_group)
        layout.addWidget(legacy_group)
        layout.addWidget(console_group)
        
        self.setLayout(layout)
    
    def log(self, message):
        self.console.append(message)
        QApplication.processEvents()

    def generate_random_passphrase(self):
        import secrets
        passphrase = secrets.token_urlsafe(4)
        self.passphrase_input.setText(passphrase)
        self.log("Generated secure passphrase (copy it now!)")
        self.copy_passphrase_btn.setEnabled(True)

    def copy_passphrase_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.passphrase_input.text())
        self.log("Passphrase copied to clipboard.")

    
    def generate_chain(self):
        # Rest of existing generate_chain logic

        try:
            if self.passphrase_check.isChecked() and not self.passphrase_input.text():
                QMessageBox.warning(self, "Passphrase Required", 
                "Please enter a passphrase or uncheck encryption")
                return

            output_dir = self.output_dir.get_path()
            org_name = self.org_name.text()
            
            self.console.clear()
            self.log(f"Generating certificate chain for PDF signing...")
            
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate Root CA
            self.log("1. Generating Root CA...")
            root_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            root_name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"{org_name} Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            
            # Self-signed Root CA certificate
            root_cert = x509.CertificateBuilder().subject_name(
                root_name
            ).issuer_name(
                root_name  # Self-signed, so issuer = subject
            ).public_key(
                root_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)  # 10 years
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=1), critical=True
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,  # Can sign certificates
                    crl_sign=True,       # Can sign CRLs
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                critical=False
            ).sign(root_key, hashes.SHA256(), default_backend())
            
            # Generate Intermediate CA
            self.log("2. Generating Intermediate CA...")
            intermediate_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            intermediate_name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"{org_name} Intermediate CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            
            # Intermediate CA certificate (signed by Root CA)
            intermediate_cert = x509.CertificateBuilder().subject_name(
                intermediate_name
            ).issuer_name(
                root_name  # Signed by Root CA
            ).public_key(
                intermediate_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1825)  # 5 years
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,  # Can sign certificates
                    crl_sign=True,       # Can sign CRLs
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
                critical=False
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False
            ).sign(root_key, hashes.SHA256(), default_backend())
            
            # Generate Signer certificate
            self.log("3. Generating Signer certificate...")
            signer_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            signer_name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"PDF Signer"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "signer@example.com"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ])
            
            # Signer certificate (signed by Intermediate CA)
            signer_cert = x509.CertificateBuilder().subject_name(
                signer_name
            ).issuer_name(
                intermediate_name  # Signed by Intermediate CA
            ).public_key(
                signer_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)  # 1 year
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,  # nonRepudiation
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            ).add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]), critical=False
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()),
                critical=False
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
                critical=False
            ).sign(intermediate_key, hashes.SHA256(), default_backend())
            
            # Save all certificates and keys
            root_cert_path = os.path.join(output_dir, "root_ca.pem")
            root_key_path = os.path.join(output_dir, "root_ca_key.pem")
            intermediate_cert_path = os.path.join(output_dir, "intermediate_ca.pem")
            intermediate_key_path = os.path.join(output_dir, "intermediate_ca_key.pem")
            signer_cert_path = os.path.join(output_dir, "signer_cert.pem")
            signer_key_path = os.path.join(output_dir, "signer_key.pem")
            
            # Save files
            self.log("4. Saving certificates and keys...")

            
            # Write Root CA certificate and key
            with open(root_cert_path, "wb") as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))

            encryption = (
                serialization.BestAvailableEncryption(
                    self.passphrase_input.text().encode()
                ) if self.passphrase_check.isChecked() else 
                serialization.NoEncryption()
            )

            with open(root_key_path, "wb") as f:
                f.write(root_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write Intermediate CA certificate and key
            with open(intermediate_cert_path, "wb") as f:
                f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(intermediate_key_path, "wb") as f:
                f.write(intermediate_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write Signer certificate and key
            with open(signer_cert_path, "wb") as f:
                f.write(signer_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(signer_key_path, "wb") as f:
                f.write(signer_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption#serialization.NoEncryption()
                ))
            #self.log(f"Root CA private key encrypted: {self.passphrase_check.isChecked()}")
            #self.log(f"Intermediate CA private key encrypted: {self.passphrase_check.isChecked()}")
            self.log(f"Signer private key encrypted: {self.passphrase_check.isChecked()}")
 
            self.log("\nCertificate chain generated successfully!")
            self.log(f"Root CA certificate: {root_cert_path}")
            self.log(f"Intermediate CA certificate: {intermediate_cert_path}")
            self.log(f"Signer certificate: {signer_cert_path}")
            self.log("\nFor signing: Use the signer_cert.pem and signer_key.pem")
            self.log("For verification: Use root_ca.pem as trust root and intermediate_ca.pem as other_cert")
            
        except Exception as e:
            self.log(f"Error generating certificate chain: {str(e)}")
    
    def generate_keys(self):
        try:
            output_dir = self.legacy_output_dir.get_path()
            
            self.console.clear()
            self.log("Generating RSA 4096 key pair and self-signed certificate...")
            self.log("Note: For a proper certificate chain, use the 'Generate Certificate Chain' button instead.")
            
            os.makedirs(output_dir, exist_ok=True)
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # Create a self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "PG Self-Signed"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PG"),
            ])
            
            """cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                # Certificate valid for 10 years
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).sign(private_key, hashes.SHA256(), default_backend())
            """
            # In the certificate generation code (e.g., generate_keys() method):
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True, 
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True
            ).sign(private_key, hashes.SHA256(), default_backend())

            encryption = (
                serialization.PrivateFormat.PKCS12.encryption_builder().
                kdf_rounds(50000).
                key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC).
                build(self.passphrase_input.text().encode()) if self.passphrase_check.isChecked() else 
                serialization.NoEncryption()
            )

            """encryption = (
                serialization.BestAvailableEncryption(
                    self.passphrase_input.text().encode()
                ) if self.passphrase_check.isChecked() else 
                serialization.NoEncryption()
            )"""
            
            # Save private key
            private_key_path = os.path.join(output_dir, "private_key.pem")
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption#serialization.NoEncryption()
                ))
            
            # Save public key
            public_key_path = os.path.join(output_dir, "public_key.pem")
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            # Save certificate
            cert_path = os.path.join(output_dir, "certificate.pem")
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            
            self.log(f"Private key saved to: {private_key_path}")
            self.log(f"Public key saved to: {public_key_path}")
            self.log(f"Certificate saved to: {cert_path}")
            
        except Exception as e:
            self.log(f"Error generating keys: {str(e)}")


class PDFSigningTab(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()
        
        # File selection group
        file_group = QGroupBox("File Selection")
        file_form = QFormLayout()
        
        self.pdf_file = FileSelectionWidget("PDF File:", "PDF Files (*.pdf)")
        self.output_file = QLineEdit()
        
        file_form.addRow(self.pdf_file)
        file_form.addRow("Output File:", self.output_file)
        file_group.setLayout(file_form)
        
        # Certificate selection group
        cert_group = QGroupBox("Certificate Selection")
        cert_form = QFormLayout()
        
        self.key_file = FileSelectionWidget("Private Key:", "Key Files (*.pem *.key)")
        self.cert_file = FileSelectionWidget("Certificate:", "Certificate Files (*.pem *.crt *.cer)")

        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Enter passphrase (if key is encrypted)")
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        cert_form.addRow("Passphrase:", self.passphrase_input)

        
        # CA Chain selection
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
        
        # Signature options group
        sig_group = QGroupBox("Signature Options")
        sig_form = QFormLayout()
        
        self.field_name = QLineEdit("Signature1")
        self.create_field = QCheckBox("Create signature field if it does not exist")
        #self.location = QLineEdit()
        #self.contact_info = QLineEdit()
        
        sig_form.addRow("Field Name:", self.field_name)
        sig_form.addRow(self.create_field)
        #sig_form.addRow("Location:", self.location)
        #sig_form.addRow("Contact Info:", self.contact_info)
        sig_group.setLayout(sig_form)

        self.signature_image_path = FileSelectionWidget("Signature Image:", "Image Files (*.jpg *.png *.bmp)")
        sig_form.addRow(self.signature_image_path)

        self.timestamp_checkbox = QCheckBox("Add timestamp")
        sig_form.addRow(self.timestamp_checkbox)
        
        # Sign button and console
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
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select CA Certificate", "", "Certificate Files (*.pem *.crt *.cer)"
        )
        if file_path:
            item = QListWidgetItem(file_path)
            self.ca_chain_list.addItem(item)
    
    def remove_ca_cert(self):
        selected_items = self.ca_chain_list.selectedItems()
        if selected_items:
            for item in selected_items:
                self.ca_chain_list.takeItem(self.ca_chain_list.row(item))
    
    def log(self, message):
        self.console.append(message)
        QApplication.processEvents()
    
    def sign_pdf(self):
        try:
            self.console.clear()
            
            if self.timestamp_checkbox.isChecked():
                signature_meta.timestamp_url = "http://timestamp.digicert.com"
                self.log("Adding timestamp to the signature.")

            # Get input and output files
            pdf_paths = self.pdf_file.get_paths()
            if not pdf_paths:
                self.log("Error: Please select a PDF file to sign.")
                return
            
            pdf_file = pdf_paths[0]
            
            output_file = self.output_file.text()
            if not output_file:
                output_file = pdf_file.replace(".pdf", "_signed.pdf")
                self.output_file.setText(output_file)
            
            # Get key and certificate
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
            
            # Get CA chain
            ca_chain = []
            for i in range(self.ca_chain_list.count()):
                ca_chain.append(self.ca_chain_list.item(i).text())
            
            # Get signature options
            field_name = self.field_name.text()
            create_field = self.create_field.isChecked()
            #location = self.location.text()
            #contact_info = self.contact_info.text()
            
            self.log(f"Signing PDF: {pdf_file}")
            self.log(f"Output file: {output_file}")
            self.log(f"Using key: {key_file}")
            self.log(f"Using certificate: {cert_file}")
            if ca_chain:
                self.log(f"Using CA chain: {', '.join(ca_chain)}")
            
            # Load the signer with certificate chain
            key_passphrase = self.passphrase_input.text().encode() if self.passphrase_input.text() else None
            self.log("Loading certificates and keys...")
            
            cms_signer = signers.SimpleSigner.load(
                key_file, cert_file,
                ca_chain_files=ca_chain,
                key_passphrase=key_passphrase
            )

            if key_passphrase:
                self.log("Using encrypted private key with passphrase.")

            # Prepare the PDF for signing
            self.log("Preparing PDF for signing...")
            with open(pdf_file, 'rb') as doc:
                w = IncrementalPdfFileWriter(doc)
                
                # Check if the signature field exists
                if create_field:
                    self.log("Creating signature field...")
                    fields.append_signature_field(
                        w, sig_field_spec=fields.SigFieldSpec(
                            sig_field_name=field_name, 
                            box=(100, 100, 300, 200)
                        )
                    )
                
                # Create signature metadata
                signature_meta = signers.PdfSignatureMetadata(
                    field_name=field_name,
                    signer_key_usage=["digital_signature", "non_repudiation"],
                    subfilter=fields.SigSeedSubFilter.PADES,
                )
                
                # Add optional metadata if provided
                #if location:
                #    signature_meta.location = location
                #if contact_info:
                #    signature_meta.contact_info = contact_info
                
                # Sign the PDF
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
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout()
        
        # File selection group
        file_group = QGroupBox("File Selection")
        file_form = QFormLayout()
        
        self.pdf_file = FileSelectionWidget("PDF File:", "PDF Files (*.pdf)")
        file_form.addRow(self.pdf_file)
        file_group.setLayout(file_form)
        
        # Certificate selection group
        cert_group = QGroupBox("Certificate Selection")
        cert_form = QFormLayout()
        
        self.trust_cert = FileSelectionWidget("Trust Root Certificate:", "Certificate Files (*.pem *.crt *.cer)")
        
        # Intermediate Certs selection
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

        # Legacy Certificate selection group
        #cert_legacy_group = QGroupBox("Legacy Certificate Selection")
        #cert_legacy_form = QFormLayout()
        
        #self.trust_legacy_cert = FileSelectionWidget("Legacy Certificate:", "Legacy Certificate Files (*.pem *.crt *.cer)")

        #cert_legacy_form.addRow(self.trust_legacy_cert)
        #cert_legacy_group.setLayout(cert_legacy_form)
        
        # Verification options group
        verify_group = QGroupBox("Verification Options")
        verify_form = QFormLayout()
        
        self.sig_index = QSpinBox()
        self.sig_index.setMinimum(-1)
        self.sig_index.setValue(-1)
        self.sig_index.setSpecialValueText("All signatures")
        
        verify_form.addRow("Signature Index:", self.sig_index)
        verify_group.setLayout(verify_form)
        
        # Verify button and console
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
        #layout.addWidget(cert_legacy_group)
        layout.addWidget(verify_group)
        layout.addWidget(self.verify_button)
        layout.addWidget(console_group)
        
        self.setLayout(layout)
    
    def add_intermediate_cert(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Intermediate Certificate", "", "Certificate Files (*.pem *.crt *.cer)"
        )
        if file_path:
            item = QListWidgetItem(file_path)
            self.intermediate_list.addItem(item)
    
    def remove_intermediate_cert(self):
        selected_items = self.intermediate_list.selectedItems()
        if selected_items:
            for item in selected_items:
                self.intermediate_list.takeItem(self.intermediate_list.row(item))
    
    def log(self, message):
        self.console.append(message)
        QApplication.processEvents()
    
    def verify_pdf(self):
        try:
            self.console.clear()
            
            # Get PDF file
            pdf_paths = self.pdf_file.get_paths()
            if not pdf_paths:
                self.log("Error: Please select a PDF file to verify.")
                return
            
            pdf_file = pdf_paths[0]
            
            # Get trust root certificate
            trust_cert_paths = self.trust_cert.get_paths()
            if not trust_cert_paths:
                self.log("Error: Please select a trust root certificate.")
                return
            
            trust_cert = trust_cert_paths[0]
            
            # Get intermediate certificates
            other_certs = []
            for i in range(self.intermediate_list.count()):
                other_certs.append(self.intermediate_list.item(i).text())
            
            # Get signature index
            signature_index = self.sig_index.value()
            if signature_index == -1:
                signature_index = None
            
            self.log(f"Verifying PDF: {pdf_file}")
            self.log(f"Using trust root: {trust_cert}")
            if other_certs:
                self.log(f"Using intermediate certificates: {', '.join(other_certs)}")
            
            # Load the trust root certificate
            self.log("Loading certificates...")
            root_cert = load_cert_from_pemder(trust_cert)
            
            # Load other certificates (typically intermediate CAs)
            other_cert_objs = []
            for cert_path in other_certs:
                try:
                    cert = load_cert_from_pemder(cert_path)
                    other_cert_objs.append(cert)
                    self.log(f"Loaded intermediate certificate: {cert_path}")
                except Exception as e:
                    self.log(f"Warning: Failed to load certificate {cert_path}: {str(e)}")
            
            # Create validation context
            self.log("Creating validation context...")
            vc = ValidationContext(
                trust_roots=[root_cert],
                other_certs=other_cert_objs
            )
            
            # Allow both digital_signature and nonRepudiation key usages
            key_usage_settings = KeyUsageConstraints(
                key_usage={'digital_signature', 'nonRepudiation'},
                #key_usage={'nonRepudiation'}
                match_all_key_usages=False
            )
            
            # Open the PDF and validate the signature(s)
            self.log("Opening PDF and validating signatures...")
            with open(pdf_file, 'rb') as doc:
                r = PdfFileReader(doc)
                sigs = r.embedded_signatures
                
                if not sigs:
                    self.log("No signatures found in the PDF.")
                    return
                    
                self.log(f"Found {len(sigs)} signatures in the PDF.")
                
                # Determine which signatures to verify
                if signature_index is not None:
                    if signature_index < 0 or signature_index >= len(sigs):
                        self.log(f"Error: Signature index {signature_index} is out of range.")
                        return
                    sig_indices = [signature_index]
                else:
                    sig_indices = range(len(sigs))
                
                # Verify the specified signature(s)
                for idx in sig_indices:
                    sig = sigs[idx]
                    self.log(f"\nVerifying signature {idx}:")
                    
                    try:
                        status = validate_pdf_signature(
                            embedded_sig=sig,
                            signer_validation_context=vc,
                            key_usage_settings=key_usage_settings
                        )
                        self.log(f"  Signer: {sig.signer_cert.subject}")
                        if hasattr(status, 'signing_time') and status.signing_time:
                            self.log(f"  Signing time: {status.signing_time}")
                        
                        if status.bottom_line == 1:
                            self.log("  ✓ Signature verification successful")
                        else:
                            self.log(f"  ✗ Signature verification failed")
                            
                        # Report document modification analysis
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
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("PDF Signing Tool")
        self.setMinimumSize(800, 600)
        
        tabs = QTabWidget()
        
        # Add tabs
        tabs.addTab(CertificateGenerationTab(), "Generate Certificates")
        tabs.addTab(PDFSigningTab(), "Sign PDF")
        tabs.addTab(PDFVerificationTab(), "Verify PDF")
        
        self.setCentralWidget(tabs)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
