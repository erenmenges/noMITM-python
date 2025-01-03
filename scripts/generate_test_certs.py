import os
from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta

def generate_test_certificates(output_dir: str):
    """Generate self-signed certificates for testing."""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate key pair for CA
    ca_key = ec.generate_private_key(ec.SECP384R1())
    
    # Generate CA certificate
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_name
    ).issuer_name(
        ca_name  # Self-signed
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).sign(ca_key, hashes.SHA256())
    
    # Generate server key pair
    server_key = ec.generate_private_key(ec.SECP384R1())
    
    # Generate server certificate
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Server"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
    ])
    
    server_cert = x509.CertificateBuilder().subject_name(
        server_name
    ).issuer_name(
        ca_name
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(ca_key, hashes.SHA256())
    
    # Generate client key pair
    client_key = ec.generate_private_key(ec.SECP384R1())
    
    # Generate client certificate
    client_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Client Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
    ])
    
    client_cert = x509.CertificateBuilder().subject_name(
        client_name
    ).issuer_name(
        ca_name
    ).public_key(
        client_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).sign(ca_key, hashes.SHA256())
    
    # Save certificates and private keys
    with open(os.path.join(output_dir, "ca.crt"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(os.path.join(output_dir, "server.crt"), "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(os.path.join(output_dir, "server.key"), "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(os.path.join(output_dir, "client.crt"), "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(os.path.join(output_dir, "client.key"), "wb") as f:
        f.write(client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

if __name__ == "__main__":
    cert_dir = "test_certs"
    generate_test_certificates(cert_dir)
    print(f"Generated test certificates in directory: {cert_dir}") 