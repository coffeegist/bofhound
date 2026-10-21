import base64
import hashlib
from datetime import datetime

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bofhound.ad.models import BloodHoundRootCA, BloodHoundEnterpriseCA, BloodHoundAIACA
import pytest
from bofhound.ad.models.bloodhound_object import BloodHoundObject


@pytest.fixture
def parsed_full_user():
    yield {
        'objectclass': 'top, person, organizationalPerson, user',
        'cn': 'Administrator',
        'description': 'Built-in account for administering the computer/domain',
        'distinguishedname': 'CN=Administrator,CN=Users,DC=test,DC=lab',
        'instancetype': '4',
        'whencreated': '20210826173042.0Z',
        'whenchanged': '20220403141221.0Z',
        'usncreated': '8196',
        'memberof': 'CN=Group Policy Creator Owners,CN=Users,DC=test,DC=lab, CN=Domain Admins,CN=Users,DC=test,DC=lab, CN=Enterprise Admins,CN=Users,DC=test,DC=lab, CN=Schema Admins,CN=Users,DC=test,DC=lab, CN=Administrators,CN=Builtin,DC=test,DC=lab',
        'usnchanged': '63985',
        'ntsecuritydescriptor': 'AQAEnIgEAACkBAAAAAAAABQAAAAEAHQEGAAAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C088UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C08+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+TkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+Tm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAB/ivvSK592RVonQNMFAgAABQAsABAAAAABAAAAHbGpRq5gWkC36P+KWNRW0gECAAAAAAAFIAAAADACAAAFACwAMAAAAAEAAAAcmrZtIpTREa69AAD4A2fBAQIAAAAAAAUgAAAAMQIAAAUALAAwAAAAAQAAAGK8BVjJvShEpeKFag9MGF4BAgAAAAAABSAAAAAxAgAABQAsAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFACwAlAACAAIAAAC6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAKAAAAQAAAQAAAFMacqsvHtARmBkAqgBAUpsBAQAAAAAAAQAAAAAFACgAAAEAAAEAAABTGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAUKAAAABQIoADABAAABAAAA3kfmkW/ZcEuVV9Y/9PPM2AEBAAAAAAAFCgAAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTBwIAAAAAGAC/AQ8AAQIAAAAAAAUgAAAAIAIAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAUAP8BDwABAQAAAAAABRIAAAABBQAAAAAABRUAAAB/ivvSK592RVonQNMAAgAAAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAA==',
        'name': 'Administrator',
        'objectguid': '7b79190e-285c-40fc-8300-0584b3ee974b',
        'useraccountcontrol': '66048',
        'badpwdcount': '0',
        'codepage': '0',
        'countrycode': '0',
        'badpasswordtime': '132919604027661803',
        'lastlogoff': '0',
        'lastlogon': '132940422420644609',
        'logonhours': '?????????????????????',
        'pwdlastset': '132836191102481334',
        'primarygroupid': '513',
        'objectsid': 'S-1-5-21-3539700351-1165401899-3544196954-500',
        'admincount': '1',
        'accountexpires': '0',
        'logoncount': '208',
        'samaccountname': 'Administrator',
        'samaccounttype': '805306368',
        'objectcategory': 'CN=Person,CN=Schema,CN=Configuration,DC=test,DC=lab',
        'iscriticalsystemobject': 'TRUE',
        'dscorepropagationdata': '20210826202656.0Z, 20210826202656.0Z, 20210826175542.0Z, 16010101181216.0Z',
        'lastlogontimestamp': '132934687411151999',
        'msds-supportedencryptiontypes': '0'
    }


def test_constructor_firstEmptyObject():
    bho = BloodHoundObject()


def test_constructor_basicFullObject(parsed_full_user):
    bho = BloodHoundObject(parsed_full_user)

    assert bho.ObjectIdentifier == 'S-1-5-21-3539700351-1165401899-3544196954-500'
    assert bho.get_distinguished_name() == 'CN=ADMINISTRATOR,CN=USERS,DC=TEST,DC=LAB'
    assert bho.Properties['whencreated'] == 1629999042

def test_merge_entry_fullOverwrite():
    bho1 = BloodHoundObject({
        'objectsid': '024929',
        'otherproperty': 1
    })

    bho2 = BloodHoundObject({
        'objectsid': '024930',
        'otherproperty': 2
    })

    bho1.merge_entry(bho2, base_preference=False)
    assert bho1.ObjectIdentifier == '024930'
    assert bho1.get_property('otherproperty') == 2


def test_merge_entry_preferBase():
    bho1 = BloodHoundObject({
        'objectsid': '024929',
        'otherproperty': 1
    })

    bho2 = BloodHoundObject({
        'objectsid': '024930',
        'otherproperty': 2
    })

    bho1.merge_entry(bho2, base_preference=True)
    assert bho1.ObjectIdentifier == '024929'
    assert bho1.get_property('otherproperty') == 1


def test_merge_entry_nonExistentBaseAttribute():
    bho1 = BloodHoundObject()
    bho2 = BloodHoundObject({
        'objectsid': '024930',
        'otherproperty': 2
    })

    bho1.merge_entry(bho2)
    assert bho1.ObjectIdentifier == '024930'


def test_merge_entry_nonExistentSourceAttribute():
    bho1 = BloodHoundObject({
        'objectsid': '024929',
        'otherproperty': 1
    })
    bho2 = BloodHoundObject()

    bho1.merge_entry(bho2, base_preference=True)
    assert bho1.ObjectIdentifier == '024929'


def test_merge_entry_emptyBaseAttributes():
    bho1 = BloodHoundObject({
        'objectsid': '',
        'distinguishedname': ''
    })
    bho2 = BloodHoundObject({
        'objectsid': '024929',
        'distinguishedname': 'DC=value'
    })

    bho1.merge_entry(bho2, base_preference=True)
    assert bho1.ObjectIdentifier == '024929'
    assert bho1.get_property('distinguishedname') == 'DC=VALUE'


def test_merge_entry_emptySourceAttributes():
    bho1 = BloodHoundObject({
        'objectsid': '',
        'distinguishedname': ''
    })
    bho2 = BloodHoundObject({
        'objectsid': '024929',
        'distinguishedname': 'DC=value'
    })

    bho2.merge_entry(bho1)
    assert bho2.ObjectIdentifier == '024929'
    assert bho2.Properties['distinguishedname'] == 'DC=VALUE'


@pytest.fixture(scope="module")
def ca_certificates():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificates = []
    for serial, year, name, path_length in [(1, 2030, "Old CA", 1), (2, 2040, "Renewed CA", 3)]:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        certificate = (x509.CertificateBuilder()
                       .subject_name(subject).issuer_name(subject)
                       .public_key(key.public_key()).serial_number(serial)
                       .not_valid_before(datetime(2020, 1, 1))
                       .not_valid_after(datetime(year, 1, 1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
                       .sign(key, hashes.SHA256()))
        certificates.append(certificate.public_bytes(serialization.Encoding.DER))
    return certificates


@pytest.mark.parametrize("ca_class", [BloodHoundRootCA, BloodHoundEnterpriseCA, BloodHoundAIACA])
@pytest.mark.parametrize("order", [(0, 1), (1, 0), (1,)])
@pytest.mark.parametrize("separator", [", ", ","])
def test_cacertificate_selects_latest_expiry(ca_class, order, separator, ca_certificates):
    value = separator.join(base64.b64encode(ca_certificates[index]).decode() for index in order)
    ca = ca_class({'cacertificate': value})
    thumbprint = hashlib.sha1(ca_certificates[1]).hexdigest().upper()
    assert ca.Properties['certthumbprint'] == thumbprint
    assert ca.Properties['certname'] == 'Renewed CA'
    assert ca.Properties['hasbasicconstraints'] is True
    assert ca.Properties['basicconstraintpathlength'] == 3
    assert ca.x509Certificate['subject'].native['common_name'] == 'Renewed CA'
    assert ca.Properties['certchain'] == ([thumbprint] if ca_class is BloodHoundRootCA else [])


@pytest.mark.parametrize("ca_class", [BloodHoundRootCA, BloodHoundEnterpriseCA, BloodHoundAIACA])
@pytest.mark.parametrize("bad", ["a", "MAA=", ""])
@pytest.mark.parametrize("bad_first", [True, False])
def test_cacertificate_skips_invalid_candidates(ca_class, bad, bad_first, ca_certificates):
    valid = base64.b64encode(ca_certificates[1]).decode()
    values = [bad, valid] if bad_first else [valid, bad]
    ca = ca_class({'cacertificate': ', '.join(values)})
    assert ca.Properties['certname'] == 'Renewed CA'
    assert ca.Properties['certthumbprint'] == hashlib.sha1(ca_certificates[1]).hexdigest().upper()


@pytest.mark.parametrize("ca_class", [BloodHoundRootCA, BloodHoundEnterpriseCA, BloodHoundAIACA])
@pytest.mark.parametrize("value, decoded", [(None, b''), ('', b''), ('a', b''), ('a, a', b''), ('bm90IGEgY2VydA==', b'not a cert'), ('MAA=', b'\x30\x00')])
def test_cacertificate_invalid_fallback(ca_class, value, decoded):
    ca = ca_class({'cacertificate': value})
    thumbprint = hashlib.sha1(decoded).hexdigest().upper()
    assert ca.x509Certificate is None
    assert ca.Properties['certname'] == thumbprint
    assert ca.Properties['certthumbprint'] == thumbprint
    assert ca.Properties['hasbasicconstraints'] is False
    assert ca.Properties['basicconstraintpathlength'] == 0


@pytest.mark.parametrize("ca_class", [BloodHoundRootCA, BloodHoundEnterpriseCA, BloodHoundAIACA])
@pytest.mark.parametrize("bad_first", [True, False])
def test_cacertificate_skips_lazy_expiry_failure(ca_class, bad_first, ca_certificates):
    # Keep the DER structure intact but replace the expiry month with 13.
    # Loading succeeds; only accessing the lazy ASN.1 date exposes the error.
    valid_bytes = ca_certificates[1]
    assert valid_bytes.count(b'400101000000Z') == 1
    malformed_bytes = valid_bytes.replace(b'400101000000Z', b'401301000000Z')
    malformed_tbs = asn1_x509.Certificate.load(malformed_bytes)['tbs_certificate']
    with pytest.raises(ValueError):
        malformed_tbs['validity']['not_after'].native

    valid = base64.b64encode(valid_bytes).decode()
    malformed = base64.b64encode(malformed_bytes).decode()
    values = [malformed, valid] if bad_first else [valid, malformed]
    ca = ca_class({'cacertificate': ', '.join(values)})
    assert ca.Properties['certthumbprint'] == hashlib.sha1(valid_bytes).hexdigest().upper()
    assert ca.Properties['certname'] == 'Renewed CA'
    assert ca.x509Certificate['validity']['not_after'].native.year == 2040
    assert ca.Properties['basicconstraintpathlength'] == 3


@pytest.mark.parametrize("ca_class", [BloodHoundRootCA, BloodHoundEnterpriseCA, BloodHoundAIACA])
@pytest.mark.parametrize("empty_first", [True, False])
def test_cacertificate_fallback_ignores_empty_candidates(ca_class, empty_first):
    values = ['', 'bm90IGEgY2VydA=='] if empty_first else ['bm90IGEgY2VydA==', '']
    ca = ca_class({'cacertificate': ', '.join(values)})
    thumbprint = hashlib.sha1(b'not a cert').hexdigest().upper()
    assert ca.x509Certificate is None
    assert ca.Properties['certthumbprint'] == thumbprint
    assert ca.Properties['certname'] == thumbprint
