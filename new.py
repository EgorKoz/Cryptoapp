# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\new.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("CryptoTusur")
        Dialog.setWindowTitle("CryptoTusur")
        Dialog.resize(800, 600)
        self.tabWidget = QtWidgets.QTabWidget(Dialog)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 800, 600))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tabWidget.sizePolicy().hasHeightForWidth())
        self.tabWidget.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.tabWidget.setFont(font)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(self.tab)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(0, 0, 791, 571))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.verticalLayout_3.addWidget(self.label)
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.label_4 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_8.addWidget(self.label_4)
        self.country_name = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.country_name.setFont(font)
        self.country_name.setObjectName("country_name")
        self.horizontalLayout_8.addWidget(self.country_name)
        self.verticalLayout_3.addLayout(self.horizontalLayout_8)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_2 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_6.addWidget(self.label_2)
        self.common_name = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.common_name.setFont(font)
        self.common_name.setObjectName("common_name")
        self.horizontalLayout_6.addWidget(self.common_name)
        self.verticalLayout_3.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.label_7 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_7.setFont(font)
        self.label_7.setObjectName("label_7")
        self.horizontalLayout_9.addWidget(self.label_7)
        self.state = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.state.setFont(font)
        self.state.setObjectName("state")
        self.horizontalLayout_9.addWidget(self.state)
        self.verticalLayout_3.addLayout(self.horizontalLayout_9)
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.horizontalLayout_10.addWidget(self.label_6)
        self.local = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.local.setFont(font)
        self.local.setObjectName("local")
        self.horizontalLayout_10.addWidget(self.local)
        self.verticalLayout_3.addLayout(self.horizontalLayout_10)
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.label_5 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout_11.addWidget(self.label_5)
        self.org = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.org.setFont(font)
        self.org.setObjectName("org")
        self.horizontalLayout_11.addWidget(self.org)
        self.verticalLayout_3.addLayout(self.horizontalLayout_11)
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        self.label_8 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_8.setFont(font)
        self.label_8.setObjectName("label_8")
        self.horizontalLayout_12.addWidget(self.label_8)
        self.org_unit = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.org_unit.setFont(font)
        self.org_unit.setObjectName("org_unit")
        self.horizontalLayout_12.addWidget(self.org_unit)
        self.verticalLayout_3.addLayout(self.horizontalLayout_12)
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        self.label_9 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.horizontalLayout_13.addWidget(self.label_9)
        self.email = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.email.setFont(font)
        self.email.setObjectName("email")
        self.horizontalLayout_13.addWidget(self.email)
        self.verticalLayout_3.addLayout(self.horizontalLayout_13)
        self.horizontalLayout_14 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_14.setObjectName("horizontalLayout_14")
        self.label_3 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_14.addWidget(self.label_3)
        self.years = QtWidgets.QLineEdit(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.years.setFont(font)
        self.years.setObjectName("years")
        self.horizontalLayout_14.addWidget(self.years)
        self.verticalLayout_3.addLayout(self.horizontalLayout_14)
        self.horizontalLayout_15 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_15.setObjectName("horizontalLayout_15")
        self.create_cert = QtWidgets.QPushButton(self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.create_cert.setFont(font)
        self.create_cert.setObjectName("create_cert")
        self.horizontalLayout_15.addWidget(self.create_cert)
        self.label_10 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        self.label_10.setText("")
        self.label_10.setObjectName("label_10")
        self.horizontalLayout_15.addWidget(self.label_10)
        self.verticalLayout_3.addLayout(self.horizontalLayout_15)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.tab_2)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(3, 3, 791, 521))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_11 = QtWidgets.QLabel(self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_11.setFont(font)
        self.label_11.setObjectName("label_11")
        self.verticalLayout_2.addWidget(self.label_11)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_13 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_13.setObjectName("label_13")
        self.horizontalLayout.addWidget(self.label_13)
        self.comboBox = QtWidgets.QComboBox(self.verticalLayoutWidget)
        self.comboBox.setObjectName("comboBox")
        self.horizontalLayout.addWidget(self.comboBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_14 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_14.setObjectName("label_14")
        self.horizontalLayout_2.addWidget(self.label_14)
        self.file_field = QtWidgets.QLineEdit(self.verticalLayoutWidget)
        self.file_field.setObjectName("file_field")
        self.horizontalLayout_2.addWidget(self.file_field)
        self.browse = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.browse.setObjectName("browse")
        self.horizontalLayout_2.addWidget(self.browse)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.create_sign = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.create_sign.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.create_sign.sizePolicy().hasHeightForWidth())
        self.create_sign.setSizePolicy(sizePolicy)
        self.create_sign.setMinimumSize(QtCore.QSize(198, 0))
        self.create_sign.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.create_sign.setObjectName("create_sign")
        self.horizontalLayout_3.addWidget(self.create_sign)
        self.label_12 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_12.setText("")
        self.label_12.setObjectName("label_12")
        self.horizontalLayout_3.addWidget(self.label_12)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.label_15 = QtWidgets.QLabel(self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_15.setFont(font)
        self.label_15.setObjectName("label_15")
        self.verticalLayout_2.addWidget(self.label_15)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.label_16 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_16.setObjectName("label_16")
        self.horizontalLayout_4.addWidget(self.label_16)
        self.comboBox_2 = QtWidgets.QComboBox(self.verticalLayoutWidget)
        self.comboBox_2.setObjectName("comboBox_2")
        self.horizontalLayout_4.addWidget(self.comboBox_2)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.delete_sign = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.delete_sign.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.delete_sign.sizePolicy().hasHeightForWidth())
        self.delete_sign.setSizePolicy(sizePolicy)
        self.delete_sign.setMinimumSize(QtCore.QSize(198, 0))
        self.delete_sign.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.delete_sign.setObjectName("delete_sign")
        self.horizontalLayout_5.addWidget(self.delete_sign)
        self.label_17 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_17.setText("")
        self.label_17.setObjectName("label_17")
        self.horizontalLayout_5.addWidget(self.label_17)
        self.verticalLayout_2.addLayout(self.horizontalLayout_5)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.tab_3)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(10, 10, 791, 521))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label_18 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_18.setFont(font)
        self.label_18.setObjectName("label_18")
        self.verticalLayout_4.addWidget(self.label_18)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.label_19 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_19.setObjectName("label_19")
        self.horizontalLayout_7.addWidget(self.label_19)
        self.comboBox_3 = QtWidgets.QComboBox(self.verticalLayoutWidget_2)
        self.comboBox_3.setObjectName("comboBox_3")
        self.horizontalLayout_7.addWidget(self.comboBox_3)
        self.verticalLayout_4.addLayout(self.horizontalLayout_7)
        self.horizontalLayout_16 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_16.setObjectName("horizontalLayout_16")
        self.label_20 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_20.setObjectName("label_20")
        self.horizontalLayout_16.addWidget(self.label_20)
        self.file_field_2 = QtWidgets.QLineEdit(self.verticalLayoutWidget_2)
        self.file_field_2.setObjectName("file_field_2")
        self.horizontalLayout_16.addWidget(self.file_field_2)
        self.browse_2 = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.browse_2.setObjectName("browse_2")
        self.horizontalLayout_16.addWidget(self.browse_2)
        self.verticalLayout_4.addLayout(self.horizontalLayout_16)
        self.horizontalLayout_18 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_18.setObjectName("horizontalLayout_18")
        self.label_23 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_23.setObjectName("label_23")
        self.horizontalLayout_18.addWidget(self.label_23)
        self.comboBox_4 = QtWidgets.QComboBox(self.verticalLayoutWidget_2)
        self.comboBox_4.setObjectName("comboBox_4")
        self.horizontalLayout_18.addWidget(self.comboBox_4)
        self.verticalLayout_4.addLayout(self.horizontalLayout_18)
        self.horizontalLayout_17 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_17.setObjectName("horizontalLayout_17")
        self.verify = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        self.verify.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.verify.sizePolicy().hasHeightForWidth())
        self.verify.setSizePolicy(sizePolicy)
        self.verify.setMinimumSize(QtCore.QSize(198, 0))
        self.verify.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.verify.setObjectName("verify")
        self.horizontalLayout_17.addWidget(self.verify)
        self.label_21 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_21.setText("")
        self.label_21.setObjectName("label_21")
        self.horizontalLayout_17.addWidget(self.label_21)
        self.verticalLayout_4.addLayout(self.horizontalLayout_17)
        self.tabWidget.addTab(self.tab_3, "")

        self.retranslateUi(Dialog)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("CryptoTusur", "CryptoTusur"))
        self.label.setText(_translate("Dialog", "Создание сертификата"))
        self.label_4.setText(_translate("Dialog", "CountryName"))
        self.label_2.setText(_translate("Dialog", "CommonName"))
        self.label_7.setText(_translate("Dialog", "StateOrProvinceName"))
        self.label_6.setText(_translate("Dialog", "LocalityName"))
        self.label_5.setText(_translate("Dialog", "OrganizationName"))
        self.label_8.setText(_translate("Dialog", "OrganizationalUnitName"))
        self.label_9.setText(_translate("Dialog", "EmailAdress"))
        self.label_3.setText(_translate("Dialog", "Years"))
        self.create_cert.setText(_translate("Dialog", "Создать"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Dialog", "Сертификат"))
        self.label_11.setText(_translate("Dialog", "Создание цифровой подписи"))
        self.label_13.setText(_translate("Dialog", "Выберите сертификат"))
        self.label_14.setText(_translate("Dialog", "Выберите файл"))
        self.browse.setText(_translate("Dialog", "Выбрать"))
        self.create_sign.setText(_translate("Dialog", "Создать"))
        self.label_15.setText(_translate("Dialog", "Удаление цифровой подписи"))
        self.label_16.setText(_translate("Dialog", "Выберите подпись"))
        self.delete_sign.setText(_translate("Dialog", "Удалить"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Dialog", "Создание цифровой подписи"))
        self.label_18.setText(_translate("Dialog", "Проверка цифровой подписи"))
        self.label_19.setText(_translate("Dialog", "Выберите открытый ключ"))
        self.label_20.setText(_translate("Dialog", "Выберите файл"))
        self.browse_2.setText(_translate("Dialog", "Выбрать"))
        self.label_23.setText(_translate("Dialog", "Выберите подпись"))
        self.verify.setText(_translate("Dialog", "Проверить"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("Dialog", "Проверка цифровой подписи"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
