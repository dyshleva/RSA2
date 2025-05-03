"""SIGNATURE APP"""
import hashlib
import subprocess
import PIL.Image
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys(private_key_name, public_key_name):
    """
    Generate public and private keys with length 4096 bits
    using RSA algorithm and save them in folder keys
    """
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-out", f"./keys/{private_key_name}",
         "-pkeyopt", "rsa_keygen_bits:4096"],
        check=True
    )

    subprocess.run(
        ["openssl", "rsa", "-pubout", "-in", f"./keys/{private_key_name}",
         "-out", f"./keys/{public_key_name}"],
        check=True
    )

def get_image_hash(path_to_img):
    """
    Returns image hash
    """
    img = np.array(PIL.Image.open(path_to_img))
    img_arr = img.flatten()

    img_arr[:4096] &= 0b11111110
    img_arr = img_arr.reshape(img_arr.shape)
    img_hash = hashlib.sha256(img_arr.tobytes()).digest()

    return img_hash

def get_signature(path_to_img, path_to_private_key):
    """
    Generate signature for image using RSA algorithm
    """
    img_hash = get_image_hash(path_to_img)

    with open(path_to_private_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    img_signature = private_key.sign(
        img_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return img_signature

def sign_image(path_to_img, signed_img_name, signature):
    """
    Embed signature inside image using LSB (Least significant bit) method
    and write new image to folder images
    """
    bits_sign = "".join([f"{byte:08b}" for byte in signature])

    img = PIL.Image.open(path_to_img, "r").convert("RGB")
    width, height = img.size
    channels = 3 # because RGB
    img_arr = np.array(img.getdata()).flatten()
    index = 0

    for i, byte in enumerate(img_arr):
        if index < 4096:
            img_arr[i] = (byte & 0b11111110) | int(bits_sign[i])
            index += 1


    PIL.Image.fromarray(
        img_arr.reshape((height, width, channels)).astype("uint8")
    ).save(signed_img_name)

def validate_signature(path_to_signed_image, path_to_public_key):
    """
    Extract signature from signed image from its least significant bits
    and validate extracted signature
    """
    sigend_img_hash = get_image_hash(path_to_signed_image)

    with open(path_to_public_key, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    signed_img = PIL.Image.open(path_to_signed_image, "r")
    signed_img_arr = np.array(signed_img.getdata()).flatten()
    singed_img_bits = "".join([bin(channel)[-1] for channel in signed_img_arr][:4096])
    extracted_sign = bytes(
        [int(singed_img_bits[i:i + 8], 2) for i in range(0, len(singed_img_bits), 8)]
    )

    try:
        public_key.verify(
            extracted_sign,
            sigend_img_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    generate_keys("private_key.pem", "public_key.pem")
    sign = get_signature("./images/test.png", "./keys/private_key.pem")
    sign_image("./images/test.png", "./images/test_signed.png", sign)
    CHECKER = validate_signature("./images/test_signed.png",
                                 "./keys/public_key.pem")

    if CHECKER:
        print("Signature is correct")
    else:
        print("Signature is incorrect")
