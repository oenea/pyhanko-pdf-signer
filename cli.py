import click
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature, KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.keys import load_cert_from_pemder

@click.group()
def cli():
    """PyHanko CLI for PDF signing and verification with certificate chain support."""
    pass

@cli.command()
@click.option('--output-dir', default='./certs', help='Directory to save the generated certificates and keys.')
@click.option('--org-name', default='Your Organization', help='Organization name to use in certificates.')
def generate_chain(output_dir, org_name):
    """Generate a complete certificate chain (root CA, intermediate CA, and signer cert)."""
    os.makedirs(output_dir, exist_ok=True)
    
    click.echo("Generating certificate chain for PDF signing...")
    
    # Generate Root CA key and certificate
    click.echo("1. Generating Root CA...")
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
    
    # Generate Intermediate CA key and certificate
    click.echo("2. Generating Intermediate CA...")
    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
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
    
    # Generate Signer key and certificate
    click.echo("3. Generating Signer certificate...")
    signer_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
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
    
    # Write Root CA certificate and key
    with open(root_cert_path, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    
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
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    click.echo("\nCertificate chain generated successfully!")
    click.echo(f"Root CA certificate: {root_cert_path}")
    click.echo(f"Intermediate CA certificate: {intermediate_cert_path}")
    click.echo(f"Signer certificate: {signer_cert_path}")
    click.echo("\nFor signing: Use the signer_cert.pem and signer_key.pem")
    click.echo("For verification: Use root_ca.pem as trust root and intermediate_ca.pem as other_cert")

@cli.command()
@click.option('--output-dir', default='.', help='Directory to save the generated keys.')
def generate_keys(output_dir):
    """Generate RSA 4096 key pair and a self-signed certificate (legacy method)."""
    os.makedirs(output_dir, exist_ok=True)
    
    click.echo("Generating RSA 4096 key pair and self-signed certificate...")
    click.echo("Note: For a proper certificate chain, use the 'generate-chain' command instead.")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Create a self-signed certificate (required for PyHanko)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PyHanko Self-Signed"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyHanko User"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
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
    
    # Save private key
    private_key_path = os.path.join(output_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
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
    
    click.echo(f"Private key saved to: {private_key_path}")
    click.echo(f"Public key saved to: {public_key_path}")
    click.echo(f"Certificate saved to: {cert_path}")

@cli.command()
@click.argument('pdf_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--key', type=click.Path(exists=True), required=True, help='Path to signer private key file.')
@click.option('--cert', type=click.Path(exists=True), required=True, help='Path to signer certificate file.')
@click.option('--ca-chain', type=click.Path(exists=True), multiple=True, 
              help='Path to CA certificate chain file(s). Can be specified multiple times.')
@click.option('--field-name', default='Signature1', help='Name of the signature field.')
@click.option('--create-field', is_flag=True, help='Create signature field if it does not exist.')
@click.option('--location', help='Location where the document was signed.')
@click.option('--contact-info', help='Contact information of the signer.')
def sign(pdf_file, output_file, key, cert, ca_chain, field_name, create_field, location, contact_info):
    """Sign a PDF file using a private key and certificate chain."""
    try:
        # Load the signer with certificate chain
        cms_signer = signers.SimpleSigner.load(
            key, cert,
            ca_chain_files=ca_chain,  # Include CA chain certificates
            key_passphrase=None  # Assuming the key is not password-protected
        )
        
        # Prepare the PDF for signing
        with open(pdf_file, 'rb') as doc:
            w = IncrementalPdfFileWriter(doc)
            
            # Check if the signature field exists
            if create_field:
                # Create new signature field
                fields.append_signature_field(
                    w, sig_field_spec=fields.SigFieldSpec(
                        sig_field_name=field_name, 
                        box=(100, 100, 300, 200)  # Defines position and size
                    )
                )
            
            # Create signature metadata
            signature_meta = signers.PdfSignatureMetadata(
                field_name=field_name,
                signer_key_usage=["digital_signature", "non_repudiation"],
                subfilter=fields.SigSeedSubFilter.PADES,
            )
            
            # Add optional metadata if provided
            if location:
                signature_meta.location = location
            if contact_info:
                signature_meta.contact_info = contact_info
            
            # Sign the PDF - Open the output file as a file object
            with open(output_file, 'wb') as out:
                signers.sign_pdf(
                    w,
                    signature_meta=signature_meta,
                    signer=cms_signer,
                    output=out
                )
            
        click.echo(f"PDF signed successfully. Output saved to: {output_file}")
    
    except Exception as e:
        click.echo(f"Error signing PDF: {str(e)}", err=True)

@cli.command()
@click.argument('pdf_file', type=click.Path(exists=True))
@click.option('--trust-cert', type=click.Path(exists=True), required=True, 
              help='Path to trust root certificate file (typically root CA).')
@click.option('--other-certs', type=click.Path(exists=True), multiple=True,
              help='Path(s) to intermediate certificates. Can be specified multiple times.')
@click.option('--signature-index', type=int, 
              help='Index of the signature to verify (0-based). If not specified, all signatures will be verified.')
def verify(pdf_file, trust_cert, other_certs, signature_index):
    """Verify PDF signatures using a trust root and optional intermediate certificates."""
    try:
        # Load the trust root certificate
        root_cert = load_cert_from_pemder(trust_cert)
        
        # Load other certificates (typically intermediate CAs)
        other_cert_objs = []
        for cert_path in other_certs:
            try:
                cert = load_cert_from_pemder(cert_path)
                other_cert_objs.append(cert)
                click.echo(f"Loaded intermediate certificate: {cert_path}")
            except Exception as e:
                click.echo(f"Warning: Failed to load certificate {cert_path}: {str(e)}", err=True)
        
        # Create validation context
        vc = ValidationContext(
            trust_roots=[root_cert],
            other_certs=other_cert_objs
        )
        
        # Allow both digital_signature and nonRepudiation key usages
        key_usage_settings = KeyUsageConstraints(
            key_usage={'digital_signature', 'nonRepudiation'}
        )
        
        # Open the PDF and validate the signature(s)
        with open(pdf_file, 'rb') as doc:
            r = PdfFileReader(doc)
            sigs = r.embedded_signatures
            
            if not sigs:
                click.echo("No signatures found in the PDF.")
                return
                
            click.echo(f"Found {len(sigs)} signatures in the PDF.")
            
            # Determine which signatures to verify
            if signature_index is not None:
                if signature_index < 0 or signature_index >= len(sigs):
                    click.echo(f"Error: Signature index {signature_index} is out of range.", err=True)
                    return
                sig_indices = [signature_index]
            else:
                sig_indices = range(len(sigs))
            
            # Verify the specified signature(s)
            for idx in sig_indices:
                sig = sigs[idx]
                click.echo(f"\nVerifying signature {idx}:")
                
                try:
                    status = validate_pdf_signature(
                        embedded_sig=sig,
                        signer_validation_context=vc,
                        key_usage_settings=key_usage_settings
                    )
                    click.echo(f"  Signer: {sig.signer_cert.subject}")
                    if hasattr(status, 'signing_time') and status.signing_time:
                        click.echo(f"  Signing time: {status.signing_time}")
                    
                    if status.bottom_line == 1:
                        click.echo("  ✓ Signature verification successful")
                    else:
                            
                        # Report document modification analysis
                        if hasattr(status, 'modification_analysis'):
                            coverage = status.modification_analysis()
                            if coverage:
                                click.echo(f"  Document coverage: {coverage.coverage_level}")
                                if not coverage.docmdp_ok:
                                    click.echo("  ⚠ Document was modified in a way that violates the permissions set by the signer")
                    
                except Exception as e:
                    click.echo(f"  ✗ Signature validation failed: {str(e)}", err=True)
            
    except Exception as e:
        click.echo(f"Error verifying PDF: {str(e)}", err=True)

if __name__ == '__main__':
    cli()
