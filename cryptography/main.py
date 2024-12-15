import threading
import socket
from dh import generate_dh_parameters, generate_dh_keys, perform_dh_key_exchange
from rsa import generate_rsa_keys, encrypt_rsa_message, decrypt_rsa_message, sign_rsa_message, verify_rsa_signature
from ecc import generate_ecc_keys, ecc_sign, ecc_verify
from aes import generate_aes_key, aes_encrypt, aes_decrypt, derive_aes_key

# Define the cryptographic functions (using your previously defined ones)
def send_rsa_message(peer, message, private_key=None, public_key=None):
    """Send a message encrypted with RSA"""
    print(f"Sending RSA encrypted message to {peer}: {message}")
    if public_key:
        encrypted_message = encrypt_rsa_message(public_key, message)
        print(f"Encrypted RSA message: {encrypted_message.hex()}")
    if private_key:
        signature = sign_rsa_message(private_key, message)
        print(f"RSA Signature: {signature.hex()}")

def receive_rsa_message(message, private_key, public_key):
    """Receive and decrypt a message with RSA"""
    print(f"Receiving RSA message: {message}")
    # Decrypt the message
    decrypted_message = decrypt_rsa_message(private_key, message)
    print(f"Decrypted RSA message: {decrypted_message}")
    # Verify the signature
    signature_valid = verify_rsa_signature(public_key, decrypted_message, signature)
    print(f"Signature valid: {signature_valid}")
    return decrypted_message

def send_ecc_message(peer, message, private_key=None, public_key=None):
    """Send a message signed with ECC"""
    print(f"Sending ECC signed message to {peer}: {message}")
    if private_key:
        signature = ecc_sign(private_key, message)
        print(f"ECC Signature: {signature.hex()}")

def receive_ecc_message(message, signature, public_key):
    """Receive and verify a message with ECC"""
    print(f"Receiving ECC message: {message}")
    valid_signature = ecc_verify(public_key, message, signature)
    print(f"ECC signature valid: {valid_signature}")
    return valid_signature

def send_aes_message(peer, message, key=None):
    """Send a message encrypted with AES"""
    print(f"Sending AES encrypted message to {peer}: {message}")
    if key:
        encrypted_message = aes_encrypt(key, message)
        print(f"AES Encrypted message: {encrypted_message['ciphertext'].hex()}")

def receive_aes_message(encrypted_message, key=None):
    """Receive and decrypt a message with AES"""
    print(f"Receiving AES message: {encrypted_message}")
    if key:
        decrypted_message = aes_decrypt(key, encrypted_message)
        print(f"AES Decrypted message: {decrypted_message}")
    return decrypted_message

def send_dh_message(peer, message, public_key=None):
    """Send a Diffie-Hellman public key to the peer"""
    print(f"Sending Diffie-Hellman public key to {peer}")
    if public_key:
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        print(f"Sent Diffie-Hellman public key: {public_key_pem.decode()}")

def start_p2p_node(port, known_peers):
    """Simulate the P2P node that listens for connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(5)
    print(f"[Server] Node is listening on port {port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[Server] Connection received from {client_address}")

        message = client_socket.recv(1024).decode('utf-8')
        print(f"[Server] Message received: {message}")
        
        if message.startswith("DH"):
            # Simulate receiving Diffie-Hellman public key and performing key exchange
            peer_public_key = load_peer_public_key(message)  # You will need to load the peer's public key
            shared_key, salt = perform_dh_key_exchange(your_dh_private_key, peer_public_key)
            print(f"Shared secret derived from Diffie-Hellman: {shared_key.hex()}")
        
        elif message.startswith("RSA"):
            # Assume message is RSA encrypted
            decrypted_message = receive_rsa_message(message, your_rsa_private_key, your_rsa_public_key)
        
        elif message.startswith("ECC"):
            # Assume message is ECC signed
            valid_signature = receive_ecc_message(message, signature, your_ecc_public_key)
        
        elif message.startswith("AES"):
            # Assume message is AES encrypted
            decrypted_message = receive_aes_message(message, your_aes_key)
        
        client_socket.send(f"Message '{message}' received successfully!".encode('utf-8'))
        client_socket.close()

def load_peer_public_key(message):
    """Simulate loading a public key from a received message."""
    # In actual code, this would parse the received PEM or another serialized format.
    return serialization.load_pem_public_key(message.encode())

def broadcast_message(message, known_peers, encryption_type="RSA", private_key=None, public_key=None, key=None):
    """Broadcast an encrypted message to all known peers."""
    print(f"[Client] Broadcasting message with {encryption_type} encryption: {message}")
    for peer in known_peers:
        send_message_to_peer(peer, message, encryption_type, private_key, public_key, key)

def send_message_to_peer(peer, message, encryption_type="RSA", private_key=None, public_key=None, key=None):
    """Send an encrypted message to a peer."""
    if encryption_type == "RSA":
        send_rsa_message(peer, message, private_key=private_key, public_key=public_key)
    elif encryption_type == "ECC":
        send_ecc_message(peer, message, private_key=private_key, public_key=public_key)
    elif encryption_type == "AES":
        send_aes_message(peer, message, key=key)
    elif encryption_type == "DH":
        send_dh_message(peer, message, public_key=public_key)
    else:
        print("Invalid encryption type.")

# Main menu options
if __name__ == "__main__":
    print("=== P2P Node with Cryptographic Functions ===")
    
    # Get P2P node configuration
    my_port = int(input("Enter port for this node: "))
    known_peer_count = int(input("Enter number of known peers: "))
    known_peers = []

    for _ in range(known_peer_count):
        ip = input("Enter peer IP: ")
        port = int(input("Enter peer port: "))
        known_peers.append((ip, port))

    # Generate Diffie-Hellman parameters and keys
    dh_parameters = generate_dh_parameters()
    your_dh_private_key, your_dh_public_key = generate_dh_keys(dh_parameters)

    # Generate RSA, ECC, and AES keys (as per your previous code)
    your_rsa_private_key, your_rsa_public_key = generate_rsa_keys()
    your_ecc_private_key, your_ecc_public_key = generate_ecc_keys()
    your_aes_key = generate_aes_key()

    # Start the P2P node in a thread
    node_thread = threading.Thread(target=start_p2p_node, args=(my_port, known_peers))
    node_thread.daemon = True
    node_thread.start()

    # Main menu options
    while True:
        print("\nOptions:")
        print("1. Send Message to a Peer")
        print("2. Broadcast Message")
        print("3. Add Peer")
        print("4. Show Peers")
        print("5. Exchange Diffie-Hellman Keys")
        print("6. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            # Send message to a peer
            peer_ip = input("Enter peer IP: ")
            peer_port = int(input("Enter peer port: "))

            while True:
                print("\nMessage Sending Options:")
                print("1. Send RSA Encrypted Message")
                print("2. Send ECC Signed Message")
                print("3. Send AES Encrypted Message")
                print("4. Send Diffie-Hellman Public Key")
                print("5. Go back to the main menu")

                msg_choice = input("Enter your choice: ").strip()

                if msg_choice == "1":
                    message = input("Enter message to send (RSA): ")
                    send_rsa_message((peer_ip, peer_port), message, public_key=your_rsa_public_key)
                    break
                elif msg_choice == "2":
                    message = input("Enter message to send (ECC): ")
                    send_ecc_message((peer_ip, peer_port), message, private_key=your_ecc_private_key)
                    break
                elif msg_choice == "3":
                    message = input("Enter message to send (AES): ")
                    send_aes_message((peer_ip, peer_port), message, key=your_aes_key)
                    break
                elif msg_choice == "4":
                    message = input("Enter message to send (Diffie-Hellman Public Key): ")
                    send_dh_message((peer_ip, peer_port), message, public_key=your_dh_public_key)
                    break
                elif msg_choice == "5":
                    break  # Go back to the main menu
                else:
                    print("Invalid choice, please try again.")

        elif choice == "2":
            # Broadcast message to all peers
            print("\nMessage Sending Options:")
            print
