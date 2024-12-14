import sys
import json
from typing import Optional
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QDoubleSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QSpacerItem,
    QSizePolicy,
    QDialog,
    QLineEdit,
    QFormLayout,
    QInputDialog,
)

from solana.rpc.api import Client
from solana.rpc.types import TxOpts
from solders.compute_budget import set_compute_unit_price  # type: ignore
from solders.keypair import Keypair  # type: ignore
from solders.pubkey import Pubkey  # type: ignore
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction  # type: ignore
from solders.message import MessageV0  # type: ignore
from PyQt5.QtCore import QThread, pyqtSignal

RPC = "https://api.mainnet-beta.solana.com"

class SolanaWalletManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Solana Wallet Manager")
        self.resize(1200, 600)
        self.wallets = {}
        self.load_wallets()

        self.init_ui()
        self.load_wallet_dropdown()
        self.center_on_screen()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        left_panel = QVBoxLayout()
        right_panel = QVBoxLayout()

        wallet_group = QGroupBox("Wallet Operations")
        wallet_layout = QGridLayout()

        wallet_button = QPushButton("Add Wallet")
        wallet_button.clicked.connect(self.add_wallet_action)
        wallet_layout.addWidget(wallet_button, 0, 0, 1, 2)

        generate_wallet_button = QPushButton("Generate Wallet")
        generate_wallet_button.clicked.connect(self.generate_wallet_action)
        wallet_layout.addWidget(generate_wallet_button, 1, 0, 1, 2)

        remove_wallet_button = QPushButton("Remove Wallet")
        remove_wallet_button.clicked.connect(self.remove_wallet_action)
        wallet_layout.addWidget(remove_wallet_button, 2, 0, 1, 2)

        wallet_group.setLayout(wallet_layout)
        left_panel.addWidget(wallet_group)

        balance_group = QGroupBox("Check Balance")
        balance_layout = QGridLayout()
        balance_layout.addWidget(QLabel("Account:"), 0, 0)
        self.balance_selector = QComboBox()
        self.balance_selector.addItem("Select Wallet")
        balance_layout.addWidget(self.balance_selector, 0, 1)

        balance_button = QPushButton("Check Balance")
        balance_button.clicked.connect(self.balance_check_action)
        balance_layout.addWidget(balance_button, 1, 0, 1, 2)

        balance_group.setLayout(balance_layout)
        left_panel.addWidget(balance_group)

        transfer_group = QGroupBox("Transfer SOL")
        transfer_layout = QGridLayout()

        transfer_layout.addWidget(QLabel("From:"), 0, 0)
        self.transfer_from_selector = QComboBox()
        self.transfer_from_selector.addItem("Select Wallet")
        transfer_layout.addWidget(self.transfer_from_selector, 0, 1)

        transfer_layout.addWidget(QLabel("To:"), 1, 0)
        self.transfer_to_selector = QComboBox()
        self.transfer_to_selector.addItem("Select Wallet")
        transfer_layout.addWidget(self.transfer_to_selector, 1, 1)

        transfer_layout.addWidget(QLabel("Amount (SOL):"), 2, 0)
        self.transfer_amount_input = QDoubleSpinBox()
        self.transfer_amount_input.setRange(0.01, 1000)
        transfer_layout.addWidget(self.transfer_amount_input, 2, 1)

        transfer_button = QPushButton("Transfer")
        transfer_button.clicked.connect(self.transfer_sol_action)
        transfer_layout.addWidget(transfer_button, 3, 0, 1, 2)

        transfer_group.setLayout(transfer_layout)
        left_panel.addWidget(transfer_group)

        recover_group = QGroupBox("Recover SOL")
        recover_layout = QGridLayout()

        recover_layout.addWidget(QLabel("From:"), 0, 0)
        self.recover_from_selector = QComboBox()
        self.recover_from_selector.addItem("Select Wallet")
        recover_layout.addWidget(self.recover_from_selector, 0, 1)

        recover_layout.addWidget(QLabel("To:"), 1, 0)
        self.recover_to_selector = QComboBox()
        self.recover_to_selector.addItem("Select Wallet")
        recover_layout.addWidget(self.recover_to_selector, 1, 1)

        recover_button = QPushButton("Recover")
        recover_button.clicked.connect(self.recover_sol_action)
        recover_layout.addWidget(recover_button, 2, 0, 1, 2)

        recover_group.setLayout(recover_layout)
        left_panel.addWidget(recover_group)

        spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        left_panel.addItem(spacer)

        # Log
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        log_group.setLayout(log_layout)
        right_panel.addWidget(log_group)

        main_layout.addLayout(left_panel, stretch=1)
        main_layout.addLayout(right_panel, stretch=3)
        self.setLayout(main_layout)

    def load_wallets(self):
        try:
            with open("wallets.json", "r") as file:
                self.wallets = json.load(file)
        except FileNotFoundError:
            self.wallets = {}

    def save_wallets(self):
        with open("wallets.json", "w") as file:
            json.dump(self.wallets, file, indent=4)

    def load_wallet_dropdown(self):
        self.balance_selector.clear()
        self.transfer_from_selector.clear()
        self.transfer_to_selector.clear()
        self.recover_from_selector.clear()
        self.recover_to_selector.clear()

        self.balance_selector.addItem("Select Wallet")
        self.transfer_from_selector.addItem("Select Wallet")
        self.transfer_to_selector.addItem("Select Wallet")
        self.recover_from_selector.addItem("Select Wallet")
        self.recover_to_selector.addItem("Select Wallet")

        for wallet_name in self.wallets.keys():
            self.balance_selector.addItem(wallet_name)
            self.transfer_from_selector.addItem(wallet_name)
            self.transfer_to_selector.addItem(wallet_name)
            self.recover_from_selector.addItem(wallet_name)
            self.recover_to_selector.addItem(wallet_name)

    def add_wallet_action(self):
        dialog = AddWalletDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            wallet_name, public_key, private_key = dialog.get_wallet_details()

            if not wallet_name or not public_key or not private_key:
                QMessageBox.warning(self, "Warning", "All fields are required.")
                return

            if not self.is_wallet_name_unique(wallet_name):
                return

            # Save Wallet
            self.wallets[wallet_name] = {"pub_key": public_key, "priv_key": private_key}
            self.save_wallets()
            self.load_wallet_dropdown()
            QMessageBox.information(self, "Success", f"Wallet '{wallet_name}' added.")

    def generate_wallet_action(self):
        wallet_name, ok_name = QInputDialog.getText(
            self, "Generate Wallet", "Enter wallet name:"
        )
        if not ok_name or not wallet_name.strip():
            return

        if not self.is_wallet_name_unique(wallet_name):
            return

        public_key, private_key = create_wallet()
        self.wallets[wallet_name] = {"pub_key": public_key, "priv_key": private_key}
        self.save_wallets()
        self.load_wallet_dropdown()
        QMessageBox.information(self, "Success", f"Wallet '{wallet_name}' generated.")
        self.log_message(f"✅ Generated Wallet | 🔑 Public Key: {public_key}")

    def remove_wallet_action(self):
        if not self.wallets:
            QMessageBox.information(self, "No Wallets", "There are no wallets to remove.")
            return

        wallet_name, ok = QInputDialog.getItem(
            self,
            "Remove Wallet",
            "Select wallet to remove:",
            list(self.wallets.keys()),
            editable=False,
        )

        if not ok or not wallet_name:
            return

        public_key = self.wallets[wallet_name]["pub_key"]
        self.log_message(f"⌛ Checking balance for '{wallet_name}'... please wait a moment...")
        QApplication.processEvents()

        try:
            balance = check_balance(RPC, public_key)
            if balance > 0:
                response = QMessageBox.warning(
                    self,
                    "Warning",
                    f"The wallet '{wallet_name}' has a balance of {balance:.2f} SOL.\n"
                    "Are you sure you want to remove it?",
                    QMessageBox.Yes | QMessageBox.Cancel,
                )
                if response != QMessageBox.Yes:
                    return
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to check balance: {e}")
            return

        del self.wallets[wallet_name]
        self.save_wallets()
        self.load_wallet_dropdown()
        QMessageBox.information(
            self, "Success", f"Wallet '{wallet_name}' has been removed."
        )
        self.log_message(f"🗑️ Removed Wallet | Name: {wallet_name}")


    def balance_check_action(self):
        wallet_name = self.balance_selector.currentText()
        if wallet_name == "Select Wallet":
            QMessageBox.warning(self, "Warning", "Select a valid wallet.")
            return

        try:
            public_key = self.wallets[wallet_name]["pub_key"]
            self.log_message(f"⌛ Checking balance for {wallet_name}...")
            self.balance_thread = BalanceCheckThread(RPC, public_key)
            self.balance_thread.result.connect(self.log_message)
            self.balance_thread.start()
        except Exception as e:
            self.log_message(f"Error: {e}")

    def transfer_sol_action(self):
        sender = self.transfer_from_selector.currentText()
        receiver = self.transfer_to_selector.currentText()
        amount = self.transfer_amount_input.value()

        if sender == "Select Wallet" or receiver == "Select Wallet":
            QMessageBox.warning(
                self, "Warning", "❌ Select valid wallets for transfer."
            )
            return

        if sender == receiver:
            QMessageBox.warning(
                self, "Warning", "❌ Sender and receiver cannot be the same."
            )
            return

        try:
            sender_priv = self.wallets[sender]["priv_key"]
            receiver_pub = self.wallets[receiver]["pub_key"]
            self.log_message(
                f"💸 Transferring {amount:.2f} SOL from {sender} to {receiver}..."
            )
            self.transfer_thread = TransferSolThread(
                RPC, sender_priv, receiver_pub, amount
            )
            self.transfer_thread.result.connect(self.log_message)
            self.transfer_thread.start()
        except Exception as e:
            self.log_message(f"Error: {e}")

    def recover_sol_action(self):
        sender = self.recover_from_selector.currentText()
        receiver = self.recover_to_selector.currentText()

        if sender == "Select Wallet" or receiver == "Select Wallet":
            QMessageBox.warning(
                self, "Warning", "❌ Select valid wallets for recovery."
            )
            return

        if sender == receiver:
            QMessageBox.warning(
                self, "Warning", "❌ Sender and receiver cannot be the same."
            )
            return

        try:
            sender_priv = self.wallets[sender]["priv_key"]
            receiver_priv = self.wallets[receiver]["priv_key"]
            self.log_message(f"↩️ Recovering funds from {sender} to {receiver}...")
            self.recover_thread = RecoverSolThread(RPC, sender_priv, receiver_priv)
            self.recover_thread.result.connect(self.log_message)
            self.recover_thread.start()
        except Exception as e:
            self.log_message(f"Error: {e}")

    def is_wallet_name_unique(self, wallet_name):
        if wallet_name in self.wallets:
            QMessageBox.warning(self, "Warning", "Wallet name already exists.")
            return False
        return True

    def log_message(self, message):
        self.log_display.append(message)

    def center_on_screen(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        frame_geometry = self.frameGeometry()
        frame_geometry.moveCenter(screen_geometry.center())
        self.move(frame_geometry.topLeft())

class BalanceCheckThread(QThread):
    result = pyqtSignal(str)

    def __init__(self, rpc_url, pub_key):
        super().__init__()
        self.rpc_url = rpc_url
        self.pub_key = pub_key

    def run(self):
        try:
            balance = check_balance(self.rpc_url, self.pub_key)
            self.result.emit(f"💰 Balance: {balance:.2f} SOL")
        except Exception as e:
            self.result.emit(f"Error: Failed to check balance: {e}")


class TransferSolThread(QThread):
    result = pyqtSignal(str)

    def __init__(self, rpc_url, sender_priv, receiver_pub, amount):
        super().__init__()
        self.rpc_url = rpc_url
        self.sender_priv = sender_priv
        self.receiver_pub = receiver_pub
        self.amount = amount

    def run(self):
        try:
            result = transfer_sol(
                self.rpc_url, self.sender_priv, self.receiver_pub, self.amount
            )
            self.result.emit(result)
        except Exception as e:
            self.result.emit(f"Error: Failed to transfer SOL: {e}")


class RecoverSolThread(QThread):
    result = pyqtSignal(str)

    def __init__(self, rpc_url, sender_priv, receiver_priv):
        super().__init__()
        self.rpc_url = rpc_url
        self.sender_priv = sender_priv
        self.receiver_priv = receiver_priv

    def run(self):
        try:
            result = recover_sol(self.rpc_url, self.sender_priv, self.receiver_priv)
            self.result.emit(result)
        except Exception as e:
            self.result.emit(f"Error: Failed to recover SOL: {e}")


class AddWalletDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Wallet")
        self.setFixedSize(650, 150)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        form_layout = QFormLayout()
        self.wallet_name_input = QLineEdit()
        self.public_key_input = QLineEdit()
        self.private_key_input = QLineEdit()

        form_layout.addRow(QLabel("Wallet Name:"), self.wallet_name_input)
        form_layout.addRow(QLabel("Public Key:"), self.public_key_input)
        form_layout.addRow(QLabel("Private Key:"), self.private_key_input)
        layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        self.add_button = QPushButton("Add")
        self.cancel_button = QPushButton("Cancel")
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.add_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

    def get_wallet_details(self):
        return (
            self.wallet_name_input.text().strip(),
            self.public_key_input.text().strip(),
            self.private_key_input.text().strip(),
        )

# Outside Functions

def create_wallet():
    keypair = Keypair()
    private_key = str(keypair)
    public_key = str(keypair.pubkey())
    return public_key, private_key

def transfer_sol(
    rpc_url: str,
    sender_priv_base58_str: str,
    receiver_pubkey_str: str,
    sol_amount: float,
) -> Optional[bool]:
    client = Client(rpc_url)
    sender_keypair = Keypair.from_base58_string(sender_priv_base58_str)
    to_pubkey = Pubkey.from_string(receiver_pubkey_str)
    lamports_amount = int(sol_amount * 1e9)

    sender_balance = client.get_balance(sender_keypair.pubkey()).value
    if sender_balance < lamports_amount:
        return "Insufficient balance for the transaction."

    instructions = [
        transfer(
            TransferParams(
                from_pubkey=sender_keypair.pubkey(),
                to_pubkey=to_pubkey,
                lamports=lamports_amount,
            )
        ),
        set_compute_unit_price(100_000),
    ]

    recent_blockhash = client.get_latest_blockhash().value.blockhash
    compiled_message = MessageV0.try_compile(
        sender_keypair.pubkey(),
        instructions,
        [],
        recent_blockhash,
    )

    try:
        txn_sig = client.send_transaction(
            txn=VersionedTransaction(compiled_message, [sender_keypair]),
            opts=TxOpts(skip_preflight=True),
        ).value

        return f"🔗 https://solscan.io/tx/{str(txn_sig)}"
    except Exception as e:
        return f"Failed to send transaction"

def recover_sol(
    rpc_url: str, sender_priv_base58_str: str, receiver_priv_base58_str: str
) -> Optional[bool]:
    client = Client(rpc_url)
    sender_keypair = Keypair.from_base58_string(sender_priv_base58_str)
    receiver_keypair = Keypair.from_base58_string(receiver_priv_base58_str)
    sender_balance = client.get_balance(sender_keypair.pubkey()).value
    if sender_balance == 0.0:
        return "❌ Insufficient balance for the transaction."

    instructions = [
        transfer(
            TransferParams(
                from_pubkey=sender_keypair.pubkey(),
                to_pubkey=receiver_keypair.pubkey(),
                lamports=sender_balance,
            )
        ),
        set_compute_unit_price(100_000),
    ]

    recent_blockhash = client.get_latest_blockhash().value.blockhash
    compiled_message = MessageV0.try_compile(
        receiver_keypair.pubkey(),
        instructions,
        [],
        recent_blockhash,
    )

    try:
        txn_sig = client.send_transaction(
            txn=VersionedTransaction(
                compiled_message, [sender_keypair, receiver_keypair]
            ),
            opts=TxOpts(skip_preflight=True),
        ).value

        return f"🔗 https://solscan.io/tx/{str(txn_sig)}"
    except Exception as e:
        return f"Failed to send transaction"

def check_balance(rpc_url: str, pub_key: str) -> float:
    client = Client(rpc_url)
    to_pubkey = Pubkey.from_string(pub_key)
    return client.get_balance(to_pubkey).value / 10**9

def main():
    app = QApplication(sys.argv)
    manager = SolanaWalletManager()
    manager.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

