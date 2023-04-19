from OpenSSL import crypto
import os
import hashlib


# def generate_self_signed_cert(common_name, country, state, city, org, org_unit, email):
#     key = crypto.PKey()
#     key.generate_key(crypto.TYPE_RSA, 2048)
#     req = crypto.X509Req()
#     req.get_subject().CN = common_name
#     req.get_subject().C = country
#     req.get_subject().ST = state
#     req.get_subject().L = city
#     req.get_subject().O = org
#     req.get_subject().OU = org_unit
#     req.get_subject().emailAddress = email
#     req.set_pubkey(key)
#     req.sign(key, "sha256")
#
#     cert = crypto.X509()
#     cert.set_serial_number(1000)
#     cert.gmtime_adj_notBefore(0)
#     cert.gmtime_adj_notAfter(315360000)
#     cert.set_issuer(cert.get_subject())
#     cert.set_subject(req.get_subject())
#     cert.set_pubkey(req.get_pubkey())
#     cert.sign(key, "sha256")
#
#     return cert, key
#
# def sign_file(file_path, cert_file, key_file):
#     with open(cert_file, "r") as f:
#         cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
#     with open(key_file, "r") as f:
#         key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
#
#     with open(file_path, "rb") as f:
#         data = f.read()
#         file_hash = hashlib.sha256(data).hexdigest()
#
#     signature = crypto.sign(key, data, "sha256")
#
#     signature_file_path = file_path + ".sig"
#     with open(signature_file_path, "wb") as f:
#         f.write(signature)
#
#     signature_info = {
#         "file": os.path.basename(file_path),
#         "hash": file_hash,
#         "cert_subject": cert.get_subject().CN,
#         "cert_issuer": cert.get_issuer().CN
#     }
#     signature_info_file_path = file_path + ".siginfo"
#     with open(signature_info_file_path, "w") as f:
#         for k, v in signature_info.items():
#             f.write(f"{k}: {v}\n")
#
#     print("File signed successfully")
#
# def unsign_file(file_path):
#     # проверяем, существует ли файл подписи и файл с информацией о подписи
#     signature_file_path = file_path + ".sig"
#     signature_info_file_path = file_path + ".siginfo"
#     if not os.path.isfile(signature_file_path):
#         print("Signature file not found")
#         return
#     if not os.path.isfile(signature_info_file_path):
#         print("Signature info file not found")
#         return
#
#     # удаляем файл подписи и файл с информацией о подписи
#     os.remove(signature_file_path)
#     os.remove(signature_info_file_path)
#
#     print("Signature removed successfully")
#
#

# common_name = input("Enter Common Name: ")
# country = input("Enter Country: ")
# state = input("Enter State: ")
# city = input("Enter City: ")
# org = input("Enter Organization: ")
# org_unit = input("Enter Organizational Unit: ")
# email = input("Enter Email: ")
# cert, key = generate_self_signed_cert(common_name, country, state, city, org, org_unit, email)
#

# with open("mycert.pem", "w") as f:
#     f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())
# with open("mykey.pem", "w") as f:
#     f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode())
#

# file_path = input("Enter file path: ")
# sign_file(file_path, "mycert.pem", "mykey.pem")
#

# file_path = input("Enter file path: ")
# unsign_file(file_path)

def verify_signature(file_name, signature_file_name, public_key_file_name):
    # Load the PEM-encoded public key from file
    with open(public_key_file_name, 'r') as f:
        public_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())

    with open(signature_file_name, 'rb') as signature_file:
        signature = signature_file.read()

    with open(file_name, 'rb') as data_file:
        data = data_file.read()

    cert = crypto.X509()
    cert.set_pubkey(public_key)
    try:
        crypto.verify(cert, signature, data, 'sha256')
        print("Signature is valid.")
        return True
    except crypto.Error as e:
        print("Error verifying signature: ", e)
        return False

verify_signature('trext.txt', 'sign/trext.txt.sig', 'certs/b_key_pub.pem')