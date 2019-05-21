from pkcs11 import (
    lib as load,
    Attribute,
    ObjectClass,
    KeyType,
    Mechanism,
    MechanismFlag,
)
from pkcs11.util import biginteger

DEFAULT_KID = b"\x00"
DEFAULT_PIN = "123456"
DEFAULT_MGMT_KEY = "010203040506070801020304050607080102030405060708"

HGH_BYTE, HGH_INT = b"\x8f", 0x8F
MID_BYTE, MID_INT = b"\xff", 0xFF
LOW_BYTE, LOW_INT = b"\x00", 0x00


def generate_keypair(session, id=DEFAULT_KID):
    capabilities = MechanismFlag.SIGN
    # NOTE: This does not  explicitly mark the private key as non-extractable
    public, private = session.generate_keypair(
        KeyType.RSA, 1024, id=id, store=True, capabilities=capabilities
    )
    return public, private


def show_private_keys(session):
    for obj in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
        print("ID(%s) - LABEL(%s)" % (obj.id, obj.label))


def get_public_key(session, key_id=DEFAULT_KID):
    return session.get_key(object_class=ObjectClass.PUBLIC_KEY, id=key_id)


def get_private_key(session, key_id=DEFAULT_KID):
    return session.get_key(object_class=ObjectClass.PRIVATE_KEY, id=key_id)


def get_yubikey():
    lib = load("/usr/local/lib/libykcs11.1.dylib")
    return lib.get_token(token_label="YubiKey PIV")


def _rsa_private_operation(private_key, data):
    # specifying RSA_X_509 as a mechanism allows for "raw" RSA operations so
    # this sign operation is equivalent to expontentiation with the private
    # exponent without hashing / padding
    mechanism = Mechanism.RSA_X_509
    return private_key.sign(data, mechanism=mechanism)


def _rsa_public_operation(public_key, data):
    public_exponent = public_key[Attribute.PUBLIC_EXPONENT]
    public_exponent = int.from_bytes(public_exponent, byteorder="big")
    modulus = public_key[Attribute.MODULUS]
    modulus = int.from_bytes(modulus, byteorder="big")
    pt = int.from_bytes(data, byteorder="big")
    ct = pow(pt, public_exponent, modulus)
    return biginteger(ct)


def _consume(expected_byte, data):
    assert expected_byte == data[0]
    return data[1:]


def decrypt(private_key, ciphertext):
    data = _rsa_private_operation(private_key, ciphertext)
    # remove garbage padding scheme
    data = _consume(HGH_INT, data)
    while data[0] != LOW_INT:
        data = _consume(MID_INT, data)
    return _consume(LOW_INT, data)


def encrypt(public_key, plaintext):
    key_length_bytes = public_key.key_length // 8
    padding_length = key_length_bytes - len(data) - 2
    if padding_length < 0:
        raise ValueError("plaintext too large")
    # garbage padding scheme!
    # all 0xff padding causes errors from the yubikey (or ykcs11/libykpiv?) but
    # a leading value of <= 0x8f seems to be fine.
    padded_data = HGH_BYTE + padding_length * MID_BYTE + LOW_BYTE + plaintext
    return _rsa_public_operation(public_key, padded_data)


if __name__ == "__main__":
    yk = get_yubikey()
    data = b"foobar!"

    # NOTE: this will overwrite the 0x00 kid private key!
    # with yk.open(rw=True, so_pin=DEFAULT_MGMT_KEY) as session:
    #     generate_keypair(session)

    with yk.open(rw=True, user_pin=DEFAULT_PIN) as session:
        public_key = get_public_key(session)
        private_key = get_private_key(session)
        ct = encrypt(public_key, data)
        pt = decrypt(private_key, ct)
        assert pt == data
