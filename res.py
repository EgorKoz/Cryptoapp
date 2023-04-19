import os
import sys
import pathlib
import hashlib

from PyQt5.QtWidgets import QDialog, QApplication, QFileDialog, QMessageBox
from new import Ui_Dialog
from OpenSSL import crypto


class MainWindow(QDialog, Ui_Dialog):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.comboBox.addItems(self.get_all_cert())
        self.create_cert.clicked.connect(self.request_create_cert)
        self.browse.clicked.connect(self.browse_files)
        self.create_sign.clicked.connect(self.create_sign_request)
        self.comboBox_2.addItems(self.get_all_sign())
        self.delete_sign.clicked.connect(self.delete_sign_request)
        self.comboBox_3.addItems(self.get_all_key())
        self.comboBox_4.addItems(self.get_all_sign())
        self.browse_2.clicked.connect(self.browse_files)
        self.verify.clicked.connect(self.verify_sign_request)

    @staticmethod
    def show_result(text):
        dialog = QMessageBox()
        dialog.setWindowTitle('Notification')
        dialog.setText(text)
        dialog.exec_()

    def verify_sign_request(self):
        key = self.comboBox_3.currentText()
        sign = self.comboBox_4.currentText()
        file = self.file_field_2.text()
        if not file:
            self.label_21.setText('Выберите файл')
        else:
            if self.verify_sign_from_request(key, sign, file):
                self.show_result('Подпись валидна')
            else:
                self.show_result('Подпись не валидна')

    @staticmethod
    def verify_sign_from_request(key, sign, file):
        with open(f'certs/{key}', 'r') as f:
            public_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())

        with open(f'sign/{sign}', 'rb') as signature_file:
            signature = signature_file.read()

        with open(file, 'rb') as data_file:
            data = data_file.read()

        cert = crypto.X509()
        cert.set_pubkey(public_key)
        try:
            crypto.verify(cert, signature, data, 'sha256')
            return True
        except crypto.Error:
            return False

    @staticmethod
    def delete_sign_from_request(file):
        signature_file_path = f'sign/{file}'
        signature_info_file_path = f'sign/{file}info'

        os.remove(signature_file_path)
        os.remove(signature_info_file_path)

    def delete_sign_request(self):
        sign = self.comboBox_2.currentText()
        self.delete_sign_from_request(sign)
        self.update_signs_data()
        self.show_result('Подпись удалена')

    def create_sign_request(self):
        cert = self.comboBox.currentText()
        key = self.comboBox.currentText().replace('cert', 'key')
        cert_path = f'certs/{cert}'
        key_path = f'certs/{key}'
        file = self.file_field.text()
        if not file:
            self.label_12.setText('Выберите файл')
        else:
            self.create_sign_from_request(cert_path, key_path, file)
            self.update_signs_data()
            self.show_result('Подпись создана')

    @staticmethod
    def create_sign_from_request(cert, key, file):
        with open(cert, "r") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        with open(key, "r") as f:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open(file, "rb") as f:
            data = f.read()
            file_hash = hashlib.sha256(data).hexdigest()

        signature = crypto.sign(key, data, "sha256")

        signature_file_path = f'sign/{os.path.basename(file)}.sig'
        with open(signature_file_path, "wb") as f:
            f.write(signature)

        signature_info = {
            "file": os.path.basename(file),
            "hash": file_hash,
            "cert_subject": cert.get_subject().CN,
            "cert_issuer": cert.get_issuer().CN, }
        signature_info_file_path = f'sign/{os.path.basename(file)}.siginfo'
        with open(signature_info_file_path, "w") as f:
            for k, v in signature_info.items():
                f.write(f"{k}: {v}\n")

    def browse_files(self):
        file, _ = QFileDialog.getOpenFileName(self, 'Open File', '', '')
        if file:
            self.file_field.setText(file)
            self.file_field_2.setText(file)

    @staticmethod
    def get_all_key():
        curr_dir = pathlib.Path('certs')
        curr_pat = "*pub*.pem"
        keys = [str(key.name) for key in curr_dir.glob(curr_pat)]
        return keys

    @staticmethod
    def get_all_sign():
        curr_dir = pathlib.Path('sign')
        curr_pat = "*.sig"
        signs = [str(sign.name) for sign in curr_dir.glob(curr_pat)]
        return signs

    def update_keys_data(self):
        self.comboBox_3.clear()
        self.comboBox_3.addItems(self.get_all_key())
        self.comboBox_3.update()

    def update_signs_data(self):
        self.comboBox_2.clear()
        self.comboBox_4.clear()
        self.comboBox_2.addItems(self.get_all_sign())
        self.comboBox_4.addItems(self.get_all_sign())
        self.comboBox_2.update()
        self.comboBox_4.update()

    @staticmethod
    def get_all_cert():
        curr_dir = pathlib.Path('certs')
        curr_pat = "*cert*.pem"
        certs = [str(cert.name) for cert in curr_dir.glob(curr_pat)]
        return certs

    def update_certs_data(self):
        self.comboBox.clear()
        self.comboBox.addItems(self.get_all_cert())
        self.comboBox.update()

    def validate_data_cert(
            self, name, country, state, city, org, org_unit, email, year):
        if not name:
            self.label_10.setText('Введите CommonName')
        elif not country:
            self.label_10.setText('Введите CountryName')
        elif len(country) != 2:
            self.label_10.setText('Некорректный CountryName')
        elif not state:
            self.label_10.setText('Введите StateOrProvinceName')
        elif not city:
            self.label_10.setText('Введите LocalityName')
        elif not org:
            self.label_10.setText('Введите OrganizationName')
        elif not org_unit:
            self.label_10.setText('Введите OrganizationalUnitName')
        elif not email:
            self.label_10.setText('Введите EmailAdress')
        elif not year:
            self.label_10.setText('Введите Years')
        elif not year.isdecimal():
            self.label_10.setText('Years должен быть числом')
        else:
            return True

    def request_create_cert(self):
        common_name = self.common_name.text()
        country = self.country_name.text()
        state = self.state.text()
        city = self.local.text()
        org = self.org.text()
        org_unit = self.org_unit.text()
        email = self.email.text()
        year = self.years.text()
        cert = ''
        key = ''

        if self.validate_data_cert(
                common_name, country, state, city, org, org_unit, email, year):
            cert, key = self.create_cert_from_request(
                common_name, country, state, city, org, org_unit, email, year)

        if cert and key:
            self.label_10.setText('Сертификат создан')
            self.common_name.setText('')
            self.country_name.setText('')
            self.state.setText('')
            self.local.setText('')
            self.org.setText('')
            self.org_unit.setText('')
            self.email.setText('')
            self.years.setText('')
            self.save_cert(cert, key, common_name)
            self.update_certs_data()
            self.update_keys_data()

    @staticmethod
    def create_cert_from_request(
            name, country, state, city, org, org_unit, email, year):

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        req = crypto.X509Req()
        req.get_subject().CN = name
        req.get_subject().C = country
        req.get_subject().ST = state
        req.get_subject().L = city
        req.get_subject().O = org
        req.get_subject().OU = org_unit
        req.get_subject().emailAddress = email
        req.set_pubkey(key)
        req.sign(key, "sha256")

        cert = crypto.X509()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(int(year) * 31557600)
        cert.set_issuer(cert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(key, "sha256")

        return cert, key

    @staticmethod
    def save_cert(cert, key, name):
        path_cert = f'certs/{name}_cert.pem'
        path_key_private = f'certs/{name}_key.pem'
        path_key_public = f'certs/{name}_key_pub.pem'
        if os.path.exists(path_cert):
            has = hash(cert)
            path_cert = f'certs/{name}_cert{has}.pem'
            path_key_private = f'certs/{name}_key{has}.pem'
            path_key_public = f'certs/{name}_key_pub{has}.pem'

        with open(path_cert, 'w') as f:
            f.write(
                crypto.dump_certificate(
                    crypto.FILETYPE_PEM,
                    cert).decode())
        with open(path_key_private, 'w') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode())
        with open(path_key_public, 'w') as f:
            f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main = MainWindow()
    main.show()

    sys.exit(app.exec_())
