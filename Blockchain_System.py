import hashlib
import time
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import tkinter as tk
from tkinter import simpledialog, messagebox

class BlockchainGUI:
    def __init__(self, root, blockchain):
        self.root = root
        self.root.title("Blockchain Simulator")
        self.root.configure(bg="#e6f7ff")  # Set a mild blue background color

        self.blockchain = blockchain

        self.selected_node = tk.StringVar()
        self.selected_node.set(0)  # Set the default value to 0

        # Menu bar
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)

        # Menu 1: Main Menu
        menu_1 = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Menu 1", menu=menu_1)
        menu_1.add_command(label="Node Selection", command=self.select_node)
        menu_1.add_command(label="Create Genesis Block", command=self.create_genesis_block)
        menu_1.add_command(label="Print Verified Transactions", command=self.print_verified_transactions)
        menu_1.add_command(label="Print Pending Transactions", command=self.print_pending_transactions)
        menu_1.add_command(label="Print Verified Blocks", command=self.print_verified_blocks)
        menu_1.add_command(label="Print Pending Blocks", command=self.print_pending_blocks)
        menu_1.add_command(label="Print Node Keys", command=self.print_node_keys)
        menu_1.add_command(label="Exit Program", command=root.destroy)

        # Menu 1.1: Node Selection
        self.node_submenu = tk.Menu(menu_1, tearoff=0)
        menu_1.add_cascade(label="Select Node", menu=self.node_submenu)
        for i in range(len(self.blockchain.authority_key_pair)):
            self.node_submenu.add_command(label=f"Node {i + 1}", command=lambda i=i: self.selected_node.set(i))
        self.node_submenu.add_command(label="Exit to Menu 1", command=lambda: self.selected_node.set(0))

        # Menu 1.1.1: Node Information
        self.node_info_submenu = tk.Menu(self.node_submenu, tearoff=0)
        self.node_submenu.add_cascade(label="Node Information", menu=self.node_info_submenu)
        self.node_info_submenu.add_command(label="Create a Transaction", command=self.create_transaction)
        self.node_info_submenu.add_command(label="Verify a Transaction", command=self.verify_transaction)
        self.node_info_submenu.add_command(label="Create a Block (if authoritative)", command=self.create_block)
        self.node_info_submenu.add_command(label="Verify Block", command=self.verify_block)
        self.node_info_submenu.add_command(label="Print Transactions Created", command=self.print_created_transactions)
        self.node_info_submenu.add_command(label="Print Pending Transactions", command=self.print_pending_transactions_node)
        self.node_info_submenu.add_command(label="Print Node Keys", command=self.print_node_keys)
        self.node_info_submenu.add_command(label="Exit to Menu 1.1", command=lambda: self.selected_node.set(0))

    def print_node_keys(self):
        keys_window = tk.Toplevel(self.root)
        keys_window.title("Node Keys")
        keys_window.configure(bg="#e6f7ff")

        text_widget = tk.Text(keys_window, wrap=tk.WORD, width=40, height=10, font=("Arial", 12), bg="#d9edf7")
        text_widget.pack(padx=20, pady=20)

        for i, key_pair in enumerate(self.blockchain.authority_key_pair):
            text_widget.insert(tk.END, f"Node {i + 1} Keys:\n")
            text_widget.insert(tk.END, f"Private Key: {key_pair.get_private_key()}\n")
            text_widget.insert(tk.END, f"Public Key: {key_pair.get_public_key()}\n\n")

        text_widget.config(state=tk.DISABLED)

        close_button = tk.Button(keys_window, text="Close", command=keys_window.destroy,
                                 font=("Arial", 12), bg="#5bc0de")
        close_button.pack(pady=10)

    def select_node(self):
        selected_node_index = int(self.selected_node.get())
        self.node_info_submenu.entryconfigure(2, state=tk.NORMAL if selected_node_index < len(self.blockchain.authority_key_pair) else tk.DISABLED)  # Enable/Disable "Create a Block" based on authority

    def print_pending_transactions_node(self):
        node_index = int(self.selected_node.get())
        pending_transactions = self.get_pending_transactions(node_index)
        self.display_results("Pending Transactions", pending_transactions)

    def create_genesis_block(self):
        self.blockchain.create_genesis_block()
        messagebox.showinfo("Create Genesis Block", "Genesis block created successfully!")


    def create_transaction(self):
        node_index = int(self.selected_node.get())
        sender_private_key = self.blockchain.authority_key_pair[node_index].private_key
        sender_address = sender_private_key.publickey()  # Use public key as the sender address
        recipient_address = simpledialog.askstring("Create Transaction", "Enter Recipient Address:")
        amount = simpledialog.askinteger("Create Transaction", "Enter Amount:")
        if recipient_address and amount is not None:
            transaction = Transaction(sender_address, recipient_address, amount)
            transaction.sign_transaction(sender_private_key)  # Sign the transaction
            self.blockchain.add_transaction(transaction)

    def verify_transaction(self):
        node_index = int(self.selected_node.get())
        transactions = self.get_pending_transactions(node_index)
        if transactions:
            transaction_index = simpledialog.askinteger("Verify Transaction", f"Select Transaction Index (0-{len(transactions)-1}):", minvalue=0, maxvalue=len(transactions)-1)
            if transaction_index is not None:
                transaction = transactions[transaction_index]
                if transaction.is_valid(self.blockchain.authority_key_pair[node_index].public_key):
                    messagebox.showinfo("Verification", "Transaction is valid!")
                else:
                    messagebox.showerror("Verification", "Transaction is NOT valid!")
        else:
            messagebox.showinfo("Verify Transaction", "No pending transactions to verify.")


    def create_block(self):
        node_index = int(self.selected_node.get())
        if node_index < len(self.blockchain.authority_key_pair):
            self.blockchain.mine_block(node_index)
            self.print_verified_blocks()  # Automatically display verified blocks after mining
        else:
            messagebox.showwarning("Create Block", "Only authoritative nodes can create blocks.")

    def verify_block(self):
        node_index = int(self.selected_node.get())
        blocks = self.get_verified_blocks(node_index)
        if blocks:
            block_index = simpledialog.askinteger("Verify Block", "Select Block Index:", minvalue=0, maxvalue=len(blocks)-1)
            if block_index is not None:
                block = blocks[block_index]
                if self.blockchain.verify_block(block):
                    messagebox.showinfo("Verification", "Block is valid!")
                else:
                    messagebox.showerror("Verification", "Block is NOT valid!")
        else:
            messagebox.showinfo("Verify Block", "No verified blocks to verify.")

    def print_created_transactions(self):
        node_index = int(self.selected_node.get())
        transactions = self.get_verified_transactions(node_index)
        self.display_results("Created Transactions", transactions)

    def print_verified_transactions(self):
        node_index = int(self.selected_node.get())
        verified_transactions = self.get_verified_transactions(node_index)
        self.display_results("Verified Transactions", verified_transactions)

    def print_pending_transactions(self):
        node_index = int(self.selected_node.get())
        pending_transactions = self.get_pending_transactions(node_index)
        if pending_transactions:
            for i, transaction in enumerate(pending_transactions):
                print(f"Pending Transaction {i + 1} - Sender: {transaction.sender_address}, Recipient: {transaction.recipient_address}, Amount: {transaction.amount}")
        else:
            print("No pending transactions.")


    def print_verified_blocks(self):
        node_index = int(self.selected_node.get())
        verified_blocks = self.get_verified_blocks(node_index)
        self.display_results("Verified Blocks", verified_blocks)

    def print_pending_blocks(self):
        node_index = int(self.selected_node.get())
        pending_blocks = self.get_pending_blocks(node_index)
        self.display_results("Pending Blocks", pending_blocks)

    def get_verified_transactions(self, node_index):
        verified_transactions = []

        # Check pending transactions
        for transaction in self.blockchain.pending_transactions:
            if isinstance(transaction, Transaction):
                if transaction.sender_address == self.blockchain.authority_key_pair[node_index].public_key or \
                        transaction.recipient_address == self.blockchain.authority_key_pair[node_index].public_key:
                    verified_transactions.append(
                        f"Transaction: {transaction.sender_address} to {transaction.recipient_address} - {transaction.amount} coins"
                    )

        # Check transactions in blocks
        for block in self.blockchain.chain:
            if self.blockchain.verify_block(block):
                for transaction in block.data:
                    if isinstance(transaction, Transaction):
                        if transaction.sender_address == self.blockchain.authority_key_pair[node_index].public_key or \
                                transaction.recipient_address == self.blockchain.authority_key_pair[node_index].public_key:
                            verified_transactions.append(
                                f"Transaction: {transaction.sender_address} to {transaction.recipient_address} - {transaction.amount} coins"
                            )

        return verified_transactions

    def get_pending_transactions(self, node_index):
        pending_transactions = []

        if node_index < len(self.blockchain.pending_transactions):
            transaction = self.blockchain.pending_transactions[node_index]
            # Ensure that transaction is a Transaction object
            if isinstance(transaction, Transaction):
                pending_transactions.append(transaction)

        return pending_transactions

    def get_verified_blocks(self, node_index):
        verified_blocks = []
        for block in self.blockchain.chain:
            if node_index < len(block.data):
                verified_blocks.append(f"Block {block.index}: Verified by Node {node_index}")
        return verified_blocks


    def get_pending_blocks(self, node_index):
        pending_blocks = []
        if node_index < len(self.blockchain.pending_transactions):
            pending_blocks.append(f"Block {len(self.blockchain.chain)}: Pending verification by Node {node_index}")
        return pending_blocks

    def display_results(self, title, data):
        result_window = tk.Toplevel(self.root)
        result_window.title(title)
        result_window.configure(bg="#e6f7ff")  # Set a mild blue background color

        text_widget = tk.Text(result_window, wrap=tk.WORD, width=40, height=10, font=("Arial", 12), bg="#d9edf7")  # Set a lighter blue color for the text widget
        text_widget.pack(padx=20, pady=20)

        for item in data:
            text_widget.insert(tk.END, f"{item}\n")

        text_widget.config(state=tk.DISABLED)  # Make the text widget read-only

        close_button = tk.Button(result_window, text="Close", command=result_window.destroy,
                                 font=("Arial", 12), bg="#5bc0de")  # Set a button background color
        close_button.pack(pady=10)




class RSA_Key_Pair:
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key

class Block:
    def __init__(self, index, creator_public_key, previous_hash, data=None, signature=None):
        self.index = index
        self.creator_public_key = creator_public_key
        self.previous_hash = previous_hash
        self.timestamp = int(time.time())
        self.data = data if data is not None else []
        self.signature = signature
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data = f"{self.index}{self.creator_public_key}{self.previous_hash}{self.timestamp}{self.data}"
        return hashlib.sha256(data.encode()).hexdigest()

    def sign_block(self, creator_private_key):
        data = SHA256.new(f"{self.index}{self.creator_public_key}{self.previous_hash}{self.timestamp}{self.data}".encode())
        signer = PKCS1_v1_5.new(creator_private_key)
        self.signature = signer.sign(data)

class Transaction:
    def __init__(self, sender_address, recipient_address, amount, timestamp=None, signature=None):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.timestamp = timestamp if timestamp is not None else int(time.time())
        self.signature = signature

    def sign_transaction(self, sender_private_key):
        h = SHA256.new(f"{self.sender_address}{self.recipient_address}{self.amount}{self.timestamp}".encode())
        signer = PKCS1_v1_5.new(sender_private_key)
        self.signature = signer.sign(h)

    def is_valid(self, public_key):
        if self.signature is None:
            return False
        h = SHA256.new(f"{self.sender_address}{self.recipient_address}{self.amount}{self.timestamp}".encode())
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(h, self.signature)

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.authority_key_pair = [RSA_Key_Pair(), RSA_Key_Pair()]

    def create_genesis_block(self):
        genesis_block = Block(0, self.authority_key_pair[0].public_key, "0", "genesis_block")
        genesis_block.sign_block(self.authority_key_pair[0].private_key)
        self.chain.append(genesis_block)

    def add_node(self, key_pair):
        self.authority_key_pair.append(key_pair)

    def add_transaction(self, transaction):
        if transaction not in self.pending_transactions:
            self.pending_transactions.append(transaction)

    def mine_block(self, authority_index):
        if not self.pending_transactions:
            return

        if authority_index >= len(self.authority_key_pair):
            return

        previous_block = self.chain[-1]

        transactions = [Transaction(
            tx.sender_address,
            tx.recipient_address,
            tx.amount,
            tx.timestamp,
            tx.signature
        ) for tx in self.pending_transactions]

        new_block = Block(
            previous_block.index + 1,
            self.authority_key_pair[authority_index].public_key,
            previous_block.hash,
            transactions
        )

        new_block.sign_block(self.authority_key_pair[authority_index].private_key)

        self.chain.append(new_block)

        self.pending_transactions = []

    def verify_block(self, block):
        if not block.signature:
            return False
        h = SHA256.new(f"{block.index}{block.creator_public_key}{block.previous_hash}{block.timestamp}{block.data}".encode())
        verifier = PKCS1_v1_5.new(block.creator_public_key)
        try:
            return verifier.verify(h, block.signature)
        except ValueError:
            return False

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.calculate_hash():
                return False

            if not self.verify_block(current_block):
                return False
        return True

if __name__ == "__main__":
    # Create a blockchain
    blockchain = Blockchain()

    # Create the genesis block
    blockchain.create_genesis_block()

    # Authority key pair for block creation
    authority_key_pair1 = blockchain.authority_key_pair[0]
    authority_key_pair2 = blockchain.authority_key_pair[1]

    # Simulate user transactions and block creation
    user1_key_pair = RSA_Key_Pair()
    print(user1_key_pair)

    user2_key_pair = RSA_Key_Pair()
    print(user2_key_pair)


    #User 1 sends 20 units to User 2 
    transaction1 = Transaction(user1_key_pair.public_key, user2_key_pair.public_key, 20)
    transaction1.sign_transaction(user1_key_pair.private_key)
    blockchain.add_transaction(transaction1)

    #User 2 sends 10 units to User 1
    transaction2 = Transaction(user2_key_pair.public_key, user1_key_pair.public_key, 10)
    transaction2.sign_transaction(user2_key_pair.private_key)
    blockchain.add_transaction(transaction2)

    #User 1 sends 5 Units to User 2
    transaction3 = Transaction(user1_key_pair.public_key, user2_key_pair.public_key, 5)
    transaction3.sign_transaction(user1_key_pair.private_key)
    blockchain.add_transaction(transaction3)


    # Mine a new block to include these transactions
    blockchain.mine_block(0)
    blockchain.mine_block(1)

    # Verify the blockchain
    is_valid = blockchain.is_chain_valid()
    print("Is blockchain valid? ", is_valid)


    # User 1 and User 2 verify their transactions
    is_transaction1_valid = transaction1.is_valid(user1_key_pair.public_key)
    is_transaction2_valid = transaction2.is_valid(user2_key_pair.public_key)
    is_transaction3_valid = transaction3.is_valid(user2_key_pair.public_key)

    print("Is transaction 1 valid? ", is_transaction1_valid) 
    print("Is transaction 2 valid? ", is_transaction2_valid) 
    print("Is transaction 3 valid? ", is_transaction3_valid) 


    # Attempt to tamper with the blockchain
    if is_valid:
        # Tampering with the block's data
        tampered_block = blockchain.chain[1]
        tampered_block.data = "Some changed data"
        is_valid_after_tampering = blockchain.is_chain_valid()
        print("Is blockchain valid after tampering? ", is_valid_after_tampering)

    root = tk.Tk()
    blockchain = Blockchain()  # Instantiate your blockchain object
    gui = BlockchainGUI(root, blockchain)
    root.mainloop()

