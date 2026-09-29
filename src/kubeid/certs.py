# ABOUTME: Generates the engineer's key and CSR, and verifies the certificate the cluster returns.
# ABOUTME: Subject is CN=<username> plus one O=<group> per Kubernetes group.
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class CertError(Exception):
    pass


@dataclass(frozen=True)
class IssuedCert:
    username: str
    groups: tuple[str, ...]
    not_before: datetime
    not_after: datetime


def generate_key():
    return ec.generate_private_key(ec.SECP256R1())


def build_csr_pem(key, username, groups):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, username)]
    attributes += [x509.NameAttribute(NameOID.ORGANIZATION_NAME, group) for group in groups]
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attributes)).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def private_key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_issued(cert_pem, key, username, groups):
    """Refuse any certificate whose identity or key differs from what was requested."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as err:
        raise CertError(f"signer returned data that is not a PEM certificate: {err}") from err
    cns = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    cn = cns[0] if len(cns) == 1 else None
    if cn != username:
        raise CertError(f"issued certificate CN {cn!r} != requested {username!r}")
    orgs = sorted(a.value for a in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
    if orgs != sorted(groups):
        raise CertError(f"issued certificate groups {orgs} != requested {sorted(groups)}")
    if _spki(cert.public_key()) != _spki(key.public_key()):
        raise CertError("issued certificate public key does not match the generated key")
    return IssuedCert(username, tuple(sorted(groups)), cert.not_valid_before_utc, cert.not_valid_after_utc)
