# This code demonstrates the algorithm of https://bitwarden.com/crypto.html
import asyncio as aio
import base64
from enum import Enum
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad, pad
from Cryptodome.Random import get_random_bytes
import argon2


class EncryptionType(Enum):
    AesCbc256_B64 = 0
    AesCbc128_HmacSha256_B64 = 1
    AesCbc256_HmacSha256_B64 = 2
    Rsa2048_OaepSha256_B64 = 3
    Rsa2048_OaepSha1_B64 = 4
    Rsa2048_OaepSha256_HmacSha256_B64 = 5
    Rsa2048_OaepSha1_HmacSha256_B64 = 6


class KdfType(Enum):
    PBKDF2_SHA256 = 0
    Argon2id = 1


ALGO = KdfType.PBKDF2_SHA256
# PBKDF2_ITER_NUM = 100000  # Old default value
PBKDF2_ITER_NUM = 600000
ARGON_ITER_NUM = 3
KDF_MEMORY = 64
KDF_PARALLELISM = 4

EMAIL = 'user@example.com'
MASTER_PWD = '123456'


def enc_string(enc_type: EncryptionType, data: bytes, iv: bytes = b'', mac: bytes = b'') -> str:
    ret = f'{enc_type.value}.'
    if iv:
        ret += base64.standard_b64encode(iv).decode() + '|'
    ret += base64.standard_b64encode(data).decode()
    if mac:
        ret += '|' + base64.standard_b64encode(mac).decode()
    return ret


def aes256_encrypt(plain: bytes, enc_key: bytes, mac_key: bytes = b'') -> str:
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
    obj_data = cipher.encrypt(pad(plain, cipher.block_size))
    if mac_key:
        h = HMAC.new(mac_key, digestmod=SHA256)
        h.update(iv)
        h.update(obj_data)
        obj_mac = h.digest()
    else:
        obj_mac = b''
    return enc_string(EncryptionType.AesCbc256_HmacSha256_B64, obj_data, iv, obj_mac)


def aes256_decrypt(cipher_text: str, enc_key: bytes, mac_key: bytes = b'') -> bytes:
    dot_pos = cipher_text.find('.')
    if cipher_text[:dot_pos] != '2':
        raise RuntimeError(f'Unsupported encryption algorithm {cipher_text[:dot_pos]}')
    parts = cipher_text[dot_pos+1:].split('|')
    if mac_key:
        obj_mac = base64.standard_b64decode(parts[-1])
        parts = parts[:-1]
    else:
        obj_mac = b''
    if len(parts) > 1:
        iv = base64.standard_b64decode(parts[0])
        obj_data = base64.standard_b64decode(parts[1])
    else:
        iv = None
        obj_data = parts[0]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
    plain = unpad(cipher.decrypt(obj_data), cipher.block_size)
    if mac_key:
        h = HMAC.new(mac_key, digestmod=SHA256)
        h.update(iv)
        h.update(obj_data)
        if h.digest() != obj_mac:
            raise RuntimeError('Failed to decrypt the data: HMAC checksum mismatch')
    return plain


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = HMAC.new(prk, t + info + bytes([i]), digestmod=SHA256).digest()
        okm += t
    return okm[:length]


async def main():
    match ALGO:
        case KdfType.PBKDF2_SHA256:
            # Master key is PBKDF2 of the master password salted with email.
            master_key = PBKDF2(MASTER_PWD, salt=EMAIL.encode(), dkLen=32,
                                count=PBKDF2_ITER_NUM, hmac_hash_module=SHA256)
            print('Master Key:', base64.standard_b64encode(master_key))
        case KdfType.Argon2id:
            # Master key is Argon2id of the master password salted with email SHA256 hash.
            salt_hash = SHA256.new(EMAIL.encode()).digest()
            master_key = argon2.low_level.hash_secret_raw(
                MASTER_PWD.encode(), salt=salt_hash, time_cost=ARGON_ITER_NUM,
                memory_cost=KDF_MEMORY*1024, parallelism=KDF_PARALLELISM, hash_len=32,
                type=argon2.Type.ID,
            )
            print('Master Key:', base64.standard_b64encode(master_key))
        case _:
            raise RuntimeError(f'Unrecognized KDF Type: {ALGO}')

    # And the master password hash is the master key salted with the master password
    # For login verification only. No security requirement, so iterations=1.
    # (Not shown in the website but) For LocalAuthorization, iterations=2.
    # This hash never uses Argon2.
    master_pwd_hash = PBKDF2(master_key, salt=MASTER_PWD.encode(), dkLen=32,
                             count=1, hmac_hash_module=SHA256)
    print('Master Password Hash:', base64.standard_b64encode(master_pwd_hash))
    print()
    # master_pwd_hash is stored in the cloud for login authentication

    # The stretched master key is the master key expanded by HKDF with 'enc' and 'mac'
    # The encryption key is used for AES-CBC-SHA256 encryption of the symmetric key
    # The MAC key is used as an HMAC checksum
    enc_key = hkdf_expand(master_key, b'enc', 32)
    mac_key = hkdf_expand(master_key, b'mac', 32)
    stretched_master_key = enc_key + mac_key
    print('Stretched Master Key:', base64.standard_b64encode(stretched_master_key))
    print('Encryption Key:', base64.standard_b64encode(enc_key))
    print('MAC Key:', base64.standard_b64encode(mac_key))
    print()

    # Generated Symmetric Key
    crypto_symmetric_key = get_random_bytes(64)
    enc_symmetric_key = crypto_symmetric_key[:32]
    mac_symmetric_key = crypto_symmetric_key[32:]
    print('Generated Symmetric Key:', base64.standard_b64encode(crypto_symmetric_key))
    print('Encryption Key:', base64.standard_b64encode(enc_symmetric_key))
    print('MAC Key:', base64.standard_b64encode(mac_symmetric_key))
    encrypted_symmetric_key = aes256_encrypt(crypto_symmetric_key, enc_key, mac_key)
    print('Protected Symmetric Key: ', encrypted_symmetric_key)
    print()
    # encrypted_symmetric_key is stored in the cloud for sync and bootstrapping new devices

    # Encryption
    secret_value = b'This is a secret.'
    cipher_str = aes256_encrypt(secret_value, enc_symmetric_key, mac_symmetric_key)
    print('The "Cipher String": ', cipher_str)
    plain_str = aes256_decrypt(cipher_str, enc_symmetric_key, mac_symmetric_key)
    print('Decrypt: ', plain_str)
    print('')


if __name__ == '__main__':
    aio.run(main())
