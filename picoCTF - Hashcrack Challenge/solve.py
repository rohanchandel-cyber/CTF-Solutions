import sys
import hashlib
import re
from pwn import *

# 1. Dynamic Connection Configuration
HOST = "verbal-sleep.picoctf.net"

if len(sys.argv) < 2:
    print("[-] Usage: python3 solve.py <PORT>")
    sys.exit(1)

PORT = int(sys.argv[1])

# 2. Function to automatically detect hash type based on string length
def identify_and_crack(hash_str):
    hash_len = len(hash_str)
    
    if hash_len == 32:
        algo = "md5"
    elif hash_len == 40:
        algo = "sha1"
    elif hash_len == 64:
        algo = "sha256"
    else:
        return None

    print(f"[*] Detected algorithm: {algo.upper()}. Cracking...")

    with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as f:
        for line in f:
            password = line.strip()
            
            if algo == "md5":
                guess = hashlib.md5(password.encode()).hexdigest()
            elif algo == "sha1":
                guess = hashlib.sha1(password.encode()).hexdigest()
            elif algo == "sha256":
                guess = hashlib.sha256(password.encode()).hexdigest()
                
            if guess == hash_str:
                print(f"[+] Found Match: {password}")
                return password
                
    return None

# 3. Interact with the Remote Server
print(f"[*] Connecting to {HOST}:{PORT}...")
io = remote(HOST, PORT)

while True:
    try:
        # Read a chunk of data from the server using standard recv timeout
        server_data = io.recv(timeout=1).decode()
        if not server_data:
            continue
            
        print(server_data, end="")
        
        # Regular Expression to find ANY valid MD5, SHA-1, or SHA-256 hash in the text
        hashes = re.findall(r'\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b', server_data)
        
        if hashes:
            target_hash = hashes[-1]
            print(f"\n[!] Extracted Valid Hash: {target_hash}")
            
            # Crack it
            plaintext_password = identify_and_crack(target_hash)
            
            if plaintext_password:
                io.sendline(plaintext_password.encode())
                print(f"[+] Sent: {plaintext_password}\n")
            else:
                print("[-] Failed to find password in rockyou.txt")
                break
                
    except EOFError:
        print("\n[*] Stream ended. Printing the final server response (The Flag):")
        try:
            print(io.recvall(timeout=2).decode())
        except Exception:
            pass
        break
