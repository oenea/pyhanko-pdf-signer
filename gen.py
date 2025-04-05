import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_certificate_chain(output_dir, org_name="Your Organization"):
    """
    Generate a complete certificate chain including root CA, intermediate CA, and an end-entity certificate.
    
    Args:
        output_dir: Directory to save the certificates and keys
        org_name: Organization name to use in the certificates
    
    Returns:
        tuple: Paths to root cert, intermediate cert, and end-entity cert
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate root CA
    print("Generating root CA certificate...")
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_name} Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    # Self-signed root certificate
    root_cert = x509.CertificateBuilder().subject_name(
        root_name
    ).issuer_name(
        root_name  # Self-signed, so issuer = subject
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
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
    ).sign(root_key, hashes.SHA256())
    
    # Generate intermediate CA
    print("Generating intermediate CA certificate...")
    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    
    intermediate_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_name} Intermediate CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    # Intermediate certificate (signed by root)
    intermediate_cert = x509.CertificateBuilder().subject_name(
        intermediate_name
    ).issuer_name(
        root_name  # Signed by root
    ).public_key(
        intermediate_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1825)  # 5 years
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
    ).sign(root_key, hashes.SHA256())
    
    # Generate end-entity certificate for signing
    print("Generating end-entity certificate for signing...")
    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    entity_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"PDF Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "signer@example.com"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    # End-entity certificate (signed by intermediate)
    entity_cert = x509.CertificateBuilder().subject_name(
        entity_name
    ).issuer_name(
        intermediate_name  # Signed by intermediate
    ).public_key(
        entity_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)  # 1 year
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,  # nonRepudiation
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,  # Cannot sign certificates
            crl_sign=False,       # Cannot sign CRLs
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ]), critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(entity_key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
        critical=False
    ).sign(intermediate_key, hashes.SHA256())
    
    # Save all certificates and keys
    root_cert_path = os.path.join(output_dir, "root_ca.pem")
    root_key_path = os.path.join(output_dir, "root_ca_key.pem")
    intermediate_cert_path = os.path.join(output_dir, "intermediate_ca.pem")
    intermediate_key_path = os.path.join(output_dir, "intermediate_ca_key.pem")
    entity_cert_path = os.path.join(output_dir, "signer_cert.pem")
    entity_key_path = os.path.join(output_dir, "signer_key.pem")
    
    # Save root CA certificate and key
    with open(root_cert_path, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(root_key_path, "wb") as f:
        f.write(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save intermediate CA certificate and key
    with open(intermediate_cert_path, "wb") as f:
        f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(intermediate_key_path, "wb") as f:
        f.write(intermediate_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save end-entity certificate and key
    with open(entity_cert_path, "wb") as f:
        f.write(entity_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(entity_key_path, "wb") as f:
        f.write(entity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print("\nCertificate chain generated successfully!")
    print(f"Root CA certificate: {root_cert_path}")
    print(f"Intermediate CA certificate: {intermediate_cert_path}")
    print(f"Signer certificate: {entity_cert_path}")
    
    return root_cert_path, intermediate_cert_path, entity_cert_path

def example_usage():
    """Example showing how to use the generated certificates with pyHanko"""
    from pyhanko.sign import signers
    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.pdf_utils.reader import PdfFileReader
    
    # Generate certificate chain
    root_cert_path, intermediate_cert_path, entity_cert_path = generate_certificate_chain("./certs")
    entity_key_path = entity_cert_path.replace("cert.pem", "key.pem")
    
    # 1. SIGNING EXAMPLE
    # Load the signer certificate and key for signing
    signer = signers.SimpleSigner.load(
        key_file=entity_key_path,       # Signer's private key
        cert_file=entity_cert_path,     # Signer's certificate
        ca_chain_files=[intermediate_cert_path]  # Include the intermediate CA in the chain
    )
    
    # Sign a PDF (assuming input.pdf exists)
    if os.path.exists("input.pdf"):
        print("\nSigning PDF...")
        signature_meta = signers.PdfSignatureMetadata(
            field_name='Signature1',
            subfilter=signers.SigSeedSubFilter.PADES,
            reason='Testing signature',
            contact_info='test@example.com'
        )
        
        with open('input.pdf', 'rb') as inf:
            with open('signed_output.pdf', 'wb') as outf:
                signers.sign_pdf(
                    PdfFileReader(inf),
                    signature_meta=signature_meta,
                    signer=signer,
                    output=outf
                )
                print("PDF signed and saved to signed_output.pdf")
    
    # 2. VERIFICATION EXAMPLE
    # For verification, use the root certificate as the trust anchor
    print("\nSetup for verification:")
    print("- Use the root certificate as trust_root")
    print("- Include the intermediate certificate in other_certs")
    print("- The signer's certificate is not needed in the validation context")
    
    # Example verification context setup (not actually verifying here)
    root_cert = load_cert_from_pemder(root_cert_path)
    intermediate_cert = load_cert_from_pemder(intermediate_cert_path)
    
    validation_context = ValidationContext(
        trust_roots=[root_cert],      # Root CA as trust anchor
        other_certs=[intermediate_cert]  # Intermediate CA to build the chain
    )
    
    print("\nValidation context is ready for PDF signature verification")

if __name__ == "__main__":
    example_usage()
