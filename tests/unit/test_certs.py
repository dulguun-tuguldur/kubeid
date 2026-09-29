# ABOUTME: Unit tests for key/CSR generation and verification of issued certificates.
# ABOUTME: Issued certs must match exactly what kubeid asked for before being written.
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kubeid.certs import CertError, build_csr_pem, generate_key, private_key_pem, verify_issued
from testca import make_ca, sign_csr


@pytest.fixture(scope="module")
def ca():
    return make_ca()


def test_generate_key_is_p256():
    key = generate_key()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp256r1"


def test_csr_subject_is_cn_user_and_o_per_group():
    key = generate_key()
    csr = x509.load_pem_x509_csr(build_csr_pem(key, "alice", ("cluster-viewer", "loans-edit")))
    assert csr.is_signature_valid
    cns = [a.value for a in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    orgs = [a.value for a in csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    assert cns == ["alice"]
    assert orgs == ["cluster-viewer", "loans-edit"]


def test_private_key_pem_round_trips():
    key = generate_key()
    loaded = serialization.load_pem_private_key(private_key_pem(key), password=None)
    assert loaded.private_numbers() == key.private_numbers()


def test_verify_issued_accepts_matching_cert(ca):
    ca_key, ca_cert = ca
    key = generate_key()
    cert_pem = sign_csr(build_csr_pem(key, "alice", ("loans-edit",)), ca_key, ca_cert, 3600)
    issued = verify_issued(cert_pem, key, "alice", ("loans-edit",))
    assert issued.username == "alice"
    assert issued.groups == ("loans-edit",)
    lifetime = issued.not_after - issued.not_before
    assert 3600 <= lifetime.total_seconds() <= 3600 + 300


def test_verify_issued_rejects_other_username(ca):
    ca_key, ca_cert = ca
    key = generate_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mallory")])
    cert_pem = sign_csr(build_csr_pem(key, "alice", ()), ca_key, ca_cert, 3600, subject=subject)
    with pytest.raises(CertError, match="CN 'mallory' != requested 'alice'"):
        verify_issued(cert_pem, key, "alice", ())


def test_verify_issued_rejects_extra_groups(ca):
    ca_key, ca_cert = ca
    key = generate_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "alice"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "loans-edit"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "system:masters"),
        ]
    )
    cert_pem = sign_csr(build_csr_pem(key, "alice", ("loans-edit",)), ca_key, ca_cert, 3600, subject=subject)
    with pytest.raises(CertError, match="groups"):
        verify_issued(cert_pem, key, "alice", ("loans-edit",))


def test_verify_issued_rejects_foreign_public_key(ca):
    ca_key, ca_cert = ca
    key = generate_key()
    other = generate_key()
    cert_pem = sign_csr(
        build_csr_pem(key, "alice", ()), ca_key, ca_cert, 3600, public_key=other.public_key()
    )
    with pytest.raises(CertError, match="public key"):
        verify_issued(cert_pem, key, "alice", ())


def test_verify_issued_rejects_garbage():
    with pytest.raises(CertError, match="not a PEM certificate"):
        verify_issued(b"not a cert", generate_key(), "alice", ())
