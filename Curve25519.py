import nacl.utils
import binascii
from nacl.public import PrivateKey, PublicKey, SealedBox
from termcolor import cprint as print_in_color

# nacl encryption library overview:
#     https://cr.yp.to/highspeed/coolnacl-20120725.pdf

# In 2017 NIST announced that Curve25519 and Curve448 would be added to
# Special Publication 800-186, which specifies approved elliptic curves
# for use by the US Federal Government
# https://en.wikipedia.org/wiki/Curve25519

# This library is a wrapper pynacl, which is a wrapper of nacl c library
# nacl c library written by Daniel Bernstein who discovered Curve25519

# pynacl (nacl wrapper): pynacl.readthedocs.io
# nacl c library: nacl.cr.yp.to
# Curve25519: en.wikipedia.org/wiki/Curve25519


def bool_do_strings_match(str1, str2):
    if len(str1) != len(str2):
            return False
    for i in range(0, len(str1)):
        char1 = str1[i]
        char2 = str2[i]
        if char1 != char2:
            return False
    return True

#turns private key into bytes string
def return_new_private_key_string():
    private_key_object = PrivateKey.generate()
    private_key_string = bytes(private_key_object)
    return private_key_string

#turns public key into bytes string
def return_new_public_key_string(private_key_string):
    private_key_object = PrivateKey(private_key_string)
    public_key_object = private_key_object.public_key
    public_key_string = bytes(public_key_object)
    return public_key_string

#generate private key
def return_new_private_key_object():
    private_key_object = PrivateKey.generate()
    return private_key_object

#generate public key
def return_new_public_key_object(private_key_object):
    public_key_object = private_key_object.public_key
    return public_key_object

#encrypt message using public key object
def encrypt_with_public_key_object(original_plaintext_string, public_key_object):
    sealed_public_key_string = SealedBox(public_key_object)
    ciphertext_string = sealed_public_key_string.encrypt(original_plaintext_string)
    return ciphertext_string

#decrypt message using private key object
def decrypt_with_private_key_object(ciphertext_string, private_key_object):
    unseal_public_key_string = SealedBox(private_key_object)
    decrypted_plaintext_string = unseal_public_key_string.decrypt(ciphertext_string)
    return decrypted_plaintext_string


def encrypt(plaintext_string):
    public_key_path = "encryption/public_key.txt"
    FILE = open(public_key_path, "r")
    public_key_string = FILE.read()
    FILE.close()
    public_key_object = PublicKey(public_key_string)
    encrypted_string = encrypt_with_public_key_object(plaintext_string, public_key_object)
    return encrypted_string

def decrypt(ciphertext_string):
    private_key_path = "encryption/private_key.txt"
    FILE = open(private_key_path, "r")
    private_key_string = FILE.read()
    FILE.close()
    private_key_object = PrivateKey(private_key_string)
    decrypted_string = decrypt_with_private_key_object(ciphertext_string, private_key_object)
    return decrypted_string

def sample_encryption_one(original_plaintext_string, private_key_object, public_key_object):
    print_in_color("original string: {0}".format(original_plaintext_string),"blue")
    ciphertext_string = encrypt(original_plaintext_string, public_key_object)
    #print in hex
    print_in_color("encrypted string: 0x{0}".format(binascii.hexlify(ciphertext_string)), "red")
    decrypted_plaintext_string = decrypt(ciphertext_string, private_key_object)
    print_in_color("decrypted string: {0}".format(decrypted_plaintext_string),"blue")
    if original_plaintext_string == decrypted_plaintext_string:
        print_in_color("SUCCESS", "blue")
    print_in_color("____________________________", "blue")


def sample_encryption_two(original_plaintext_string, private_key_object, public_key_object):
    print_in_color("len(original string): {0}".format(len(original_plaintext_string)),"blue")
    ciphertext_string = encrypt(original_plaintext_string, public_key_object)
    #print in hex
    print_in_color("len(encrypted string): {0}".format(len(ciphertext_string)), "red")
    decrypted_plaintext_string = decrypt(ciphertext_string, private_key_object)
    print_in_color("len(decrypted string): {0}".format(len(decrypted_plaintext_string)),"blue")
    if original_plaintext_string == decrypted_plaintext_string:
        print_in_color("SUCCESS", "blue")
    print_in_color("____________________________", "blue")


#calling all functions above
def test_one():

    # private_key_string = return_new_private_key_string()
    # public_key_string = return_new_public_key_string(private_key_string)

    private_key_object = return_new_private_key_object()
    public_key_object = return_new_public_key_object(private_key_object)

    zipped_directory_object = open("FED30APSE100A.zip", "rb")
    zipped_directory_string = zipped_directory_object.read()
    plaintext_string = "hello world"

    sample_encryption_one(plaintext_string, private_key_object, public_key_object)
    sample_encryption_two(zipped_directory_string, private_key_object, public_key_object)

def new_key_pair():
    private_key_path = "encryption/private_key.txt"
    private_key_object = return_new_private_key_object()
    private_key_string = bytes(private_key_object)
    FILE1 = open(private_key_path, "w")
    FILE1.write(private_key_string)
    FILE1.close()

    public_key_path = "encryption/public_key.txt"
    public_key_object = return_new_public_key_object(private_key_object)
    public_key_string = bytes(public_key_object)
    FILE2 = open(public_key_path, "w")
    FILE2.write(public_key_string)
    FILE2.close()


# if __name__ == "__main__":
#     test_one()



