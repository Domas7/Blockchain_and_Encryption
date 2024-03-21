import random
import math
import tkinter as tk


def is_prime(number):
    if number < 2:
        return False
    for i in range(2, number // 2 + 1):
        if number % i == 0:
            return False
    return True


def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime


def calculate_n(p, q):
    return p * q


def calculate_phi(p, q): # Euler's totient function to calculate less than n coprime
    # Euler's totient function to calculate less than n coprime
    return (p - 1) * (q - 1)


def generate_public_key(phi):
    e = random.randint(3, phi - 1)
    while math.gcd(e, phi) != 1:  # Checking if e and phi are coprime
        e = random.randint(3, phi - 1)
    return e


def calculate_private_key(e, phi):
    for d in range(3, phi):
        if (e * d) % phi == 1:
            return d
    raise ValueError(f"Could not find a mod inverse for {e} and {phi}")


def encrypt_message(message, e, n):
    message_encoded = [ord(char) for char in message] #
    encrypted_message = [pow(char, e, n) for char in message_encoded]#
    print("Message encoded:", message_encoded)
    print("Encrypted message:", encrypted_message)
    return encrypted_message


# Decrypting the message by raising each character to the power of d and modding it by n
def decrypt_message(encrypted_message, d, n):
    decrypted_message = [pow(char, d, n) for char in encrypted_message]
    message = "".join(chr(char)
                      for char in decrypted_message if 0 <= char <= 0x10FFFF)  #
    return message


# Decrypting the message with the private key
def decrypt_with_private_key(private_key_entry, encrypted_message_entry, decrypted_result):
    private_key = private_key_entry.get()
    try:
        # Splitting the private key into d and n
        d, n = map(int, private_key.split(','))
    except ValueError:
        decrypted_result.set("Invalid private key format")
        return

    # Getting the encrypted message from the entry
    encrypted_message = encrypted_message_entry.get()
    # Splitting the encrypted message into a list
    encrypted_message = encrypted_message.split(',')
    # Converting the list of strings to a list of ints
    encrypted_message = [int(char) for char in encrypted_message]

    decrypted_message = decrypt_message(
        encrypted_message, d, n)  # Decrypting the message
    decrypted_result.set(decrypted_message)


# Encrypting the message with the public key
def encrypt_decrypt_message(message_entry, public_key_result, encrypted_result):
    message = message_entry.get()
    public_key = public_key_result.get()
    if public_key:
        public_key_str = public_key.split(': ')[1].strip('()')
        e, n = map(int, public_key_str.split(', '))
        encrypted_message = encrypt_message(message, e, n)
        encrypted_result.set(encrypted_message)


def generate_new_key_pair(public_key_result, private_key_result):
    p, q = generate_prime(1000, 5000), generate_prime(1000, 5000)

    while p == q:
        q = generate_prime(1000, 5000)

    n = calculate_n(p, q)
    phi = calculate_phi(p, q)
    e = generate_public_key(phi)
    d = calculate_private_key(e, phi)

    public_key_result.set(f"Public Key (e, n): ({e}, {n})")
    private_key_result.set(f"Private Key (d, n): ({d}, {n})")


app = tk.Tk()
app.title("RSA Algorithm")
container = tk.Frame(app)  # Create a container frame to hold the two columns
container.pack(fill='both', expand=True)

# Define the two columns, one is gonna be Sender the other is Receiver
frame_left = tk.Frame(container, background='light blue')
frame_right = tk.Frame(container, background='light yellow')

# Pack the left and right columns
frame_left.pack(side='left', fill='both', expand=True)

frame_right.pack(side='right', fill='both', expand=True)

# Function to create input fields for specifying a custom public key


def create_custom_public_key_frame(parent_frame):
    custom_public_key_frame = tk.Frame(parent_frame)
    custom_public_key_frame.pack()

    e_label = tk.Label(custom_public_key_frame, text="Enter e:")
    e_label.pack()
    e_entry = tk.Entry(custom_public_key_frame)
    e_entry.pack()

    n_label = tk.Label(custom_public_key_frame, text="Enter n:")
    n_label.pack()
    n_entry = tk.Entry(custom_public_key_frame)
    n_entry.pack()

    message_label = tk.Label(custom_public_key_frame, text="Enter Message:")
    message_label.pack()
    message_entry = tk.Entry(custom_public_key_frame)
    message_entry.pack()

    # Create an "Encrypt" button
    encrypt_button = tk.Button(custom_public_key_frame, text="Encrypt",
                               command=lambda: encrypt_custom_message(e_entry, n_entry, message_entry, encrypted_result1))
    encrypt_button.pack()

    return e_entry, n_entry


custom_e_entry, custom_n_entry = create_custom_public_key_frame(frame_left)


def encrypt_custom_message(e_entry, n_entry, message_entry, encrypted_result):
    e = int(e_entry.get())
    n = int(n_entry.get())
    message = message_entry.get()

    encrypted_message = encrypt_message(message, e, n)
    encrypted_result.set(encrypted_message)


user_a_label = tk.Label(frame_left, text="Sender", background='light blue')
user_a_label.pack(side='top', padx=5, pady=5)
user_b_label = tk.Label(frame_right, text="Receiver",
                        background='light yellow')
user_b_label.pack(side='top', padx=5, pady=5)

# Sender side
frame1 = tk.Frame(frame_left)
frame1.pack()

message_label1 = tk.Label(frame1, text="Message:")
message_label1.pack()

message_entry1 = tk.Entry(frame1)
message_entry1.pack()

public_key_result1 = tk.StringVar()
public_key_result1.set(f"Public Key (e, n):")
public_key_label1 = tk.Label(frame1, textvariable=public_key_result1)
public_key_label1.pack()

private_key_result1 = tk.StringVar()
private_key_result1.set(f"Private Key (d, n):")
private_key_label1 = tk.Label(frame1, textvariable=private_key_result1)
private_key_label1.pack()

encrypt_button1 = tk.Button(frame1, text="Encrypt", command=lambda: encrypt_decrypt_message(
    message_entry1, public_key_result1, encrypted_result1))
encrypt_button1.pack()

encrypted_result1 = tk.StringVar()
encrypted_label1 = tk.Label(frame1, text="Encrypted Message:")
encrypted_label1.pack()
encrypted_message_label1 = tk.Label(frame1, textvariable=encrypted_result1)
encrypted_message_label1.pack()

encrypted_message_entry1 = tk.Entry(frame1)
encrypted_message_entry1.pack()

decrypt_button1 = tk.Button(frame1, text="Decrypt", command=lambda: decrypt_with_private_key(
    private_key_entry1, encrypted_message_entry1, decrypted_result1))
decrypt_button1.pack()

decrypted_result1 = tk.StringVar()
decrypted_label1 = tk.Label(frame1, text="Decrypted Message:")
decrypted_label1.pack()
decrypted_message_label1 = tk.Label(frame1, textvariable=decrypted_result1)
decrypted_message_label1.pack()

private_key_label1 = tk.Label(frame1, text="Private Key (d):")
private_key_label1.pack()

private_key_entry1 = tk.Entry(frame1)
private_key_entry1.pack()

generate_new_key_button1 = tk.Button(frame1, text="Generate New Key Pair",
                                     command=lambda: generate_new_key_pair(public_key_result1, private_key_result1))
generate_new_key_button1.pack()


# Receiver Side
frame2 = tk.Frame(frame_right)
frame2.pack()

message_label2 = tk.Label(frame2, text="Message:")
message_label2.pack()

message_entry2 = tk.Entry(frame2)
message_entry2.pack()

public_key_result2 = tk.StringVar()
public_key_result2.set(f"Public Key (e, n):")
public_key_label2 = tk.Label(frame2, textvariable=public_key_result2)
public_key_label2.pack()

private_key_result2 = tk.StringVar()

private_key_result2.set(f"Private Key (d, n):")
private_key_label2 = tk.Label(frame2, textvariable=private_key_result2)
private_key_label2.pack()

encrypt_button2 = tk.Button(frame2, text="Encrypt", command=lambda: encrypt_decrypt_message(
    message_entry2, public_key_result2, encrypted_result2))
encrypt_button2.pack()

encrypted_result2 = tk.StringVar()
encrypted_label2 = tk.Label(frame2, text="Encrypted Message:")
encrypted_label2.pack()
encrypted_message_label2 = tk.Label(frame2, textvariable=encrypted_result2)
encrypted_message_label2.pack()

encrypted_message_entry2 = tk.Entry(frame2)
encrypted_message_entry2.pack()

decrypt_button2 = tk.Button(frame2, text="Decrypt", command=lambda: decrypt_with_private_key(
    private_key_entry2, encrypted_message_entry2, decrypted_result2))
decrypt_button2.pack()

decrypted_result2 = tk.StringVar()
decrypted_label2 = tk.Label(frame2, text="Decrypted Message:")
decrypted_label2.pack()
decrypted_message_label2 = tk.Label(frame2, textvariable=decrypted_result2)
decrypted_message_label2.pack()

private_key_label2 = tk.Label(frame2, text="Private Key (d):")
private_key_label2.pack()

private_key_entry2 = tk.Entry(frame2)
private_key_entry2.pack()

generate_new_key_button2 = tk.Button(frame2, text="Generate New Key Pair",
                                     command=lambda: generate_new_key_pair(public_key_result2, private_key_result2))
generate_new_key_button2.pack()

app.mainloop()
