from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image
import numpy as np


# 簡易ブロック暗号化関数
def diy_block_cipher_encrypt(block, key):
    """
    簡易ブロック暗号化: 各バイトをキーの対応するバイトで加算（mod 256）
    """
    return bytes((block[i] + key[i % len(key)]) % 256 for i in range(len(block)))


def diy_block_cipher_decrypt(block, key):
    """
    簡易ブロック復号化: 各バイトをキーの対応するバイトで減算（mod 256）
    """
    return bytes((block[i] - key[i % len(key)]) % 256 for i in range(len(block)))


# ECBモード暗号化
def diy_encrypt_ecb(data, key, block_size):
    encrypted_data = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))  # パディング
        encrypted_data.extend(diy_block_cipher_encrypt(block, key))
    return bytes(encrypted_data)


# ECBモード復号
def diy_decrypt_ecb(data, key, block_size):
    decrypted_data = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        decrypted_data.extend(diy_block_cipher_decrypt(block, key))
    return bytes(decrypted_data)


# CBCモード暗号化
def diy_encrypt_cbc(data, key, block_size, iv):
    encrypted_data = bytearray()
    previous_block = iv
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))  # パディング
        xored_block = bytes(block[j] ^ previous_block[j] for j in range(block_size))
        encrypted_block = diy_block_cipher_encrypt(xored_block, key)
        encrypted_data.extend(encrypted_block)
        previous_block = encrypted_block
    return bytes(encrypted_data)


# CBCモード復号
def diy_decrypt_cbc(data, key, block_size, iv):
    decrypted_data = bytearray()
    previous_block = iv
    for i in range(0, len(data), block_size):
        encrypted_block = data[i:i + block_size]
        xored_block = diy_block_cipher_decrypt(encrypted_block, key)
        decrypted_block = bytes(xored_block[j] ^ previous_block[j] for j in range(block_size))
        decrypted_data.extend(decrypted_block)
        previous_block = encrypted_block
    return bytes(decrypted_data)


# ライブラリベースの暗号化関数
def lib_encrypt_image(data, key, mode, iv=None):
    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# ライブラリベースの復号関数
def lib_decrypt_image(data, key, mode, iv=None):
    cipher = Cipher(algorithms.AES(key), mode)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


# 共通処理
def process_image(input_image_path, output_ecb_encrypted, output_cbc_encrypted,
                  output_ecb_decrypted, output_cbc_decrypted, key, iv, block_size, use_diy=False):
    # 画像の読み込み
    img = Image.open(input_image_path).convert('RGB')
    pixel_data = np.array(img)
    flat_data = pixel_data.tobytes()

    # パディングの追加（PKCS7形式）
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(flat_data) + padder.finalize()

    # 暗号化・復号の実行
    if use_diy:
        # 自作関数を使用
        encrypted_ecb = diy_encrypt_ecb(padded_data, key, block_size)
        decrypted_ecb = diy_decrypt_ecb(encrypted_ecb, key, block_size)

        encrypted_cbc = diy_encrypt_cbc(padded_data, key, block_size, iv)
        decrypted_cbc = diy_decrypt_cbc(encrypted_cbc, key, block_size, iv)
    else:
        # ライブラリを使用
        encrypted_ecb = lib_encrypt_image(padded_data, key, modes.ECB())
        decrypted_ecb = lib_decrypt_image(encrypted_ecb, key, modes.ECB())

        encrypted_cbc = lib_encrypt_image(padded_data, key, modes.CBC(iv))
        decrypted_cbc = lib_decrypt_image(encrypted_cbc, key, modes.CBC(iv))

    # パディングを削除（ECBモード）
    unpadder_ecb = padding.PKCS7(block_size * 8).unpadder()
    decrypted_ecb = unpadder_ecb.update(decrypted_ecb) + unpadder_ecb.finalize()

    # パディングを削除（CBCモード） - 別のunpadderを作成
    unpadder_cbc = padding.PKCS7(block_size * 8).unpadder()
    decrypted_cbc = unpadder_cbc.update(decrypted_cbc) + unpadder_cbc.finalize()

    # データサイズを元の画像サイズに一致させる
    decrypted_ecb = decrypted_ecb[:len(flat_data)]
    decrypted_cbc = decrypted_cbc[:len(flat_data)]

    # 画像の保存
    save_image(encrypted_ecb[:len(flat_data)], pixel_data.shape, output_ecb_encrypted)
    save_image(decrypted_ecb, pixel_data.shape, output_ecb_decrypted)
    save_image(encrypted_cbc[:len(flat_data)], pixel_data.shape, output_cbc_encrypted)
    save_image(decrypted_cbc, pixel_data.shape, output_cbc_decrypted)


# 保存用関数
def save_image(data, img_size, output_path):
    img_data = np.frombuffer(data, dtype=np.uint8).reshape(img_size)
    Image.fromarray(img_data).save(output_path)


# メイン処理
def main():
    input_image_path = 'test.bmp'
    block_size = 16
    key = b'simplekey1234567'
    iv = b'initialvector123'

    # 自作関数で処理
    process_image(input_image_path, 'diy_ecb_encrypted.bmp', 'diy_cbc_encrypted.bmp',
                  'diy_ecb_decrypted.bmp', 'diy_cbc_decrypted.bmp', key, iv, block_size, use_diy=True)

    # ライブラリで処理
    process_image(input_image_path, 'lib_ecb_encrypted.bmp', 'lib_cbc_encrypted.bmp',
                  'lib_ecb_decrypted.bmp', 'lib_cbc_decrypted.bmp', key, iv, block_size, use_diy=False)


if __name__ == "__main__":
    main()
