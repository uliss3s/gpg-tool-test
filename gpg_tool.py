import sys
import os
import gnupg
import hashlib
import subprocess
import argparse

from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QFileDialog, QMessageBox, QDesktopWidget, QComboBox, QDialog, QVBoxLayout, QCheckBox
from tempfile import TemporaryDirectory


class GPGTool(QMainWindow):
    def __init__(self):
        super().__init__()

        self.gpg = gnupg.GPG()
        self.selected_file = None
        self.decrypted_file_hash = None
        self.temp_dir = None

        self.init_ui()
        self.update_recipients_list()

    def init_ui(self):
        self.setWindowTitle("GPG Tool")

        # Get the screen size and set the window size to half the screen size
        screen = QDesktopWidget().screenGeometry()
        width, height = screen.width() // 2, screen.height() // 2
        self.setGeometry(0, 0, width, height)
        self.move((screen.width() - width) // 2, (screen.height() - height) // 2)

        # File selection button
        self.select_file_btn = QPushButton("Select file", self)
        self.select_file_btn.setGeometry(20, 20, 100, 30)
        self.select_file_btn.clicked.connect(self.select_file)

        # File label
        self.file_label = QLabel(self)
        self.file_label.setGeometry(20, 60, width - 40, 20)
        self.file_label.setText("No file selected")

        # Recipients label
        self.recipients_label = QLabel("Available Recipients:", self)
        self.recipients_label.setGeometry(20, 100, width - 40, 20)

        # Recipients combo box
        self.recipients_combo_box = QComboBox(self)
        self.recipients_combo_box.setGeometry(20, 130, width - 40, 30)
        self.update_recipients_list()

        # Encrypt new files button
        self.encrypt_new_files_btn = QPushButton("Encrypt New Files", self)
        self.encrypt_new_files_btn.setGeometry(20, height - 100, 150, 30)
        self.encrypt_new_files_btn.clicked.connect(self.open_encrypt_new_files_dialog)

        # Lock button
        self.lock_btn = QPushButton("Lock", self)
        self.lock_btn.setGeometry(20, height - 60, 100, 30)
        self.lock_btn.clicked.connect(self.lock_file)
        self.lock_btn.setEnabled(False)

        # Unlock button
        self.unlock_btn = QPushButton("Unlock", self)
        self.unlock_btn.setGeometry(width // 2, height - 60, 100, 30)
        self.unlock_btn.clicked.connect(self.unlock_file)
        self.unlock_btn.setEnabled(False)

        self.show()

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "GPG Files (*.gpg);;All Files (*)")
        if file_path:
            self.selected_file = file_path
            self.file_label.setText(f"Selected file: {self.selected_file}")

            is_gpg = self.selected_file.endswith(".gpg")
            self.lock_btn.setEnabled(not is_gpg)
            self.unlock_btn.setEnabled(is_gpg)

            self.update_recipients_list()

    def open_encrypt_new_files_dialog(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Encrypt", "", "All Files (*)")

        if file_paths:
            # Get the selected recipient from the list
            selected_keyid = self.recipients_combo_box.currentData()
            if selected_keyid is None:
                QMessageBox.warning(self, "Warning", "Please select a recipient from the list.")
                return

            file_encrypt_dialog = FileEncryptDialog(self, file_paths, self.gpg, selected_keyid)
            file_encrypt_dialog.exec_()

    def encrypt_new_files(self, file_paths):
        # Get the selected recipient from the list
        selected_keyid = self.recipients_combo_box.currentData()
        if selected_keyid is None:
            QMessageBox.warning(self, "Warning", "Please select a recipient from the list.")
            return

        for file_path in file_paths:
            with open(file_path, "rb") as file:
                output_file = file_path + ".gpg"
                result = self.gpg.encrypt_file(file, recipients=[selected_keyid], output=output_file)

            if result.status == "encryption ok":
                print(f"Encrypted {file_path} to {output_file}")
            else:
                print(f"Failed to encrypt {file_path}")

    def update_recipients_list(self):
        keys = self.gpg.list_keys()
        self.recipients_combo_box.clear()
        self.recipients_combo_box.addItem("Select a recipient...", None)
        for key in keys:
            for uid in key["uids"]:
                self.recipients_combo_box.addItem(uid, key["keyid"])  # Set the key ID as data for the item

    def open_file_explorer(self, directory):
        if sys.platform == 'win32':
            subprocess.Popen(['explorer', directory])
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', directory])
        else:
            subprocess.Popen(['xdg-open', directory])

    def lock_file(self):
        if not self.selected_file or not self.temp_dir:
            return

        decrypted_file_path = os.path.join(self.temp_dir.name, os.path.basename(self.selected_file[:-4]))
        with open(decrypted_file_path, "rb") as file:
            current_decrypted_file_hash = hashlib.sha256(file.read()).hexdigest()

        if self.decrypted_file_hash != current_decrypted_file_hash:
            # Get the selected recipient from the list
            selected_keyid = self.recipients_combo_box.currentData()
            if selected_keyid is None:
                QMessageBox.warning(self, "Warning", "Please select a recipient from the list.")
                return

            with open(decrypted_file_path, "rb") as file:
                output_file = self.selected_file + ".gpg" if not self.selected_file.endswith(
                    ".gpg") else self.selected_file
                result = self.gpg.encrypt_file(file, recipients=[selected_keyid], output=output_file)

            if result.status == "encryption ok":
                self.selected_file = output_file

        # Update the button states outside the conditional block
        self.file_label.setText(f"Selected file: {self.selected_file}")
        self.lock_btn.setEnabled(False)
        self.unlock_btn.setEnabled(True)

        # Reset the decrypted_file_hash after locking the file
        self.decrypted_file_hash = None

        # Clear the temporary directory after locking the file
        if self.temp_dir and os.path.exists(self.temp_dir.name):
            self.temp_dir.cleanup()
            self.temp_dir = None

    def unlock_file(self):
        if not self.selected_file or self.selected_file[-4:] != ".gpg":
            return

        self.temp_dir = TemporaryDirectory()
        decrypted_file_path = os.path.join(self.temp_dir.name, os.path.basename(self.selected_file[:-4]))

        with open(self.selected_file, "rb") as encrypted_file:
            result = self.gpg.decrypt_file(encrypted_file, output=decrypted_file_path)

            if result.status == "decryption ok":
                print(f"Decryption status: {result.status}")
                print(f"Decryption stderr: {result.stderr}")
                print(f"Decrypted file path: {decrypted_file_path}")

                self.file_label.setText(f"Unlocked file: {decrypted_file_path}")
                self.lock_btn.setEnabled(True)
                self.unlock_btn.setEnabled(False)

                # Store the hash of the decrypted file
                with open(decrypted_file_path, "rb") as file:
                    self.decrypted_file_hash = hashlib.sha256(file.read()).hexdigest()

                # Open the file explorer in the temporary directory
                self.open_file_explorer(self.temp_dir.name)

            else:
                print(f"Decryption status: {result.status}")
                print(f"Decryption stderr: {result.stderr}")

                QMessageBox.warning(self, "Error", "Failed to decrypt the file.")
                self.temp_dir.cleanup()

    def closeEvent(self, event):
        if self.temp_dir and os.path.exists(self.temp_dir.name):
            decrypted_file_path = os.path.join(self.temp_dir.name, os.path.basename(self.selected_file[:-4]))
            with open(decrypted_file_path, "rb") as file:
                current_decrypted_file_hash = hashlib.sha256(file.read()).hexdigest()

            if self.decrypted_file_hash != current_decrypted_file_hash:
                self.lock_file()

            self.temp_dir.cleanup()
            self.temp_dir = None

        event.accept()


class FileEncryptDialog(QDialog):
    def __init__(self, parent, files_to_encrypt, gpg, recipient):
        super().__init__(parent)

        self.files_to_encrypt = files_to_encrypt
        self.file_checkboxes = []
        self.gpg = gpg
        self.recipient = recipient

        self.setWindowTitle("Encrypt Files")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        for file in files_to_encrypt:
            checkbox = QCheckBox(file, self)
            layout.addWidget(checkbox)
            self.file_checkboxes.append(checkbox)

        encrypt_button = QPushButton("Encrypt Selected Files", self)
        encrypt_button.clicked.connect(self.encrypt_files)
        layout.addWidget(encrypt_button)

        self.setLayout(layout)

    def encrypt_files(self):
        for checkbox in self.file_checkboxes:
            if checkbox.isChecked():
                self.encrypt_file(checkbox.text())

        self.accept()

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as file:
            output_file = file_path + ".gpg"
            result = self.gpg.encrypt_file(file, recipients=[self.recipient], output=output_file)

            if result.status == "encryption ok":
                print(f"Encrypted file: {output_file}")
            else:
                print(f"Encryption failed: {result.status}")
                print(f"Encryption stderr: {result.stderr}")


def main():
    parser = argparse.ArgumentParser(description="GPG Tool: Encrypt or decrypt a file using GPG.")
    parser.add_argument("-f", "--file-path", help="The path to the file you want to process.", default=None, required=False)

    args = parser.parse_args()

    if args.file_path:
        if os.path.exists(args.file_path):
            if not args.file_path.endswith(".gpg"):
                print(f"The file {args.file_path} is not a .gpg file")
                exit(1)
        else:
            print(f"Path {args.file_path} does not exist")
            exit(1)

    app = QApplication(sys.argv)
    gpg_tool = GPGTool()

    # Pre-select the file if the file-path argument is provided
    if args.file_path:
        gpg_tool.selected_file = args.file_path
        gpg_tool.file_label.setText(f"Selected file: {gpg_tool.selected_file}")

        is_gpg = gpg_tool.selected_file.endswith(".gpg")
        gpg_tool.lock_btn.setEnabled(not is_gpg)
        gpg_tool.unlock_btn.setEnabled(is_gpg)

    gpg_tool.show()
    sys.exit(app.exec_())

main()
