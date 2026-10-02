
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 0.5


def get_port(prompt):
    try:
        port = int(input(prompt))
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    print("Invalid port. Enter a number from 1 to 65535.")
    return None


def get_local_target():
    print("Use only systems you own or have permission to test.")
    target = input("Target IP/hostname [127.0.0.1]: ").strip()
    return target or "127.0.0.1"


# FEATURE 1: TCP Port Scanner
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((target, port)) == 0:
                return port
    except (socket.error, OSError):
        pass
    return None


def port_scanner():
    target = get_local_target()

    try:
        start = int(input("Start port (1-65535): "))
        end = int(input("End port (1-65535): "))
        if not (1 <= start <= end <= 65535):
            raise ValueError
        # Prevent accidental very large scans.
        if end - start > 2000:
            print("For this demo, scan at most 2001 ports at a time.")
            return
        socket.gethostbyname(target)
    except (ValueError, socket.gaierror):
        print("Invalid target or port range.")
        return

    print(f"\nScanning {target}: ports {start}-{end}")
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = pool.map(
            lambda p: scan_port(target, p), range(start, end + 1)
        )
        for port in results:
            if port is not None:
                open_ports.append(port)
                print(f"[OPEN] Port {port}")

    if not open_ports:
        print("No open TCP ports found in this range.")
    print("Scan completed.")


# FEATURE 2: Banner Grabber
def banner_grabber():
    target = get_local_target()
    port = get_port("Port: ")
    if port is None:
        return

    try:
        with socket.create_connection((target, port), timeout=3) as sock:
            sock.settimeout(3)
            # Some servers send a banner immediately.
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                banner = b""

            # HTTP servers usually wait for a request first.
            if not banner and port in (80, 8080, 8000):
                request = (
                    f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n"
                )
                sock.sendall(request.encode())
                try:
                    banner = sock.recv(1024)
                except socket.timeout:
                    pass

            if banner:
                print("\nBanner/response:")
                print(banner.decode("utf-8", errors="replace"))
            else:
                print("Connected, but the server sent no banner.")
    except (OSError, socket.timeout) as error:
        print(f"Connection failed: {error}")


# FEATURE 3: TCP Client and Server
def tcp_server():
    host = "127.0.0.1"
    port = get_port("TCP server port (example 5000): ")
    if port is None:
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(5)
            print(f"TCP server listening on {host}:{port}")
            print("Press Ctrl+C to stop.")

            while True:
                conn, address = server.accept()
                with conn:
                    print(f"\nConnected: {address}")
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        message = data.decode("utf-8", errors="replace")
                        print(f"Client: {message}")
                        conn.sendall(b"Message received by TCP server")
    except KeyboardInterrupt:
        print("\nTCP server stopped.")
    except OSError as error:
        print(f"TCP server error: {error}")


def tcp_client():
    host = input("Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = get_port("TCP server port: ")
    if port is None:
        return

    try:
        with socket.create_connection((host, port), timeout=5) as client:
            print("Connected. Type 'exit' to disconnect.")
            while True:
                message = input("You: ")
                if message.lower() == "exit":
                    break
                client.sendall(message.encode("utf-8"))
                response = client.recv(4096)
                print("Server:", response.decode("utf-8", errors="replace"))
    except OSError as error:
        print(f"TCP client error: {error}")


# FEATURE 4: UDP Client and Server
def udp_server():
    host = "127.0.0.1"
    port = get_port("UDP server port (example 5001): ")
    if port is None:
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind((host, port))
            print(f"UDP server listening on {host}:{port}")
            print("Press Ctrl+C to stop.")

            while True:
                data, address = server.recvfrom(4096)
                message = data.decode("utf-8", errors="replace")
                print(f"\n{address}: {message}")
                server.sendto(b"Message received by UDP server", address)
    except KeyboardInterrupt:
        print("\nUDP server stopped.")
    except OSError as error:
        print(f"UDP server error: {error}")


def udp_client():
    host = input("Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = get_port("UDP server port: ")
    if port is None:
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            print("Type 'exit' to disconnect.")
            while True:
                message = input("You: ")
                if message.lower() == "exit":
                    break
                client.sendto(message.encode("utf-8"), (host, port))
                try:
                    data, _ = client.recvfrom(4096)
                    print("Server:", data.decode("utf-8", errors="replace"))
                except socket.timeout:
                    print("No response received.")
    except OSError as error:
        print(f"UDP client error: {error}")


# FEATURE 5: Multi-client Chat Application
chat_clients = {}
chat_lock = threading.Lock()


def broadcast(message, sender=None):
    with chat_lock:
        clients = list(chat_clients.items())

    for client, name in clients:
        if client is sender:
            continue
        try:
            client.sendall((message + "\n").encode("utf-8"))
        except OSError:
            pass


def handle_chat_client(conn, address):
    name = None
    reader = None

    try:
        conn.settimeout(300)
        reader = conn.makefile("r", encoding="utf-8", errors="replace")
        conn.sendall(b"Enter your name to join: ")
        name = reader.readline().strip()[:30]

        if not name:
            return

        with chat_lock:
            chat_clients[conn] = name

        conn.sendall(
            b"Welcome! Commands: /join, /msg your message, /leave\n"
        )
        broadcast(f"* {name} joined the chat *", sender=conn)
        print(f"{name} joined from {address}")

        for line in reader:
            message = line.strip()
            if not message:
                continue

            if message == "/leave":
                break
            elif message == "/join":
                conn.sendall(b"You are already in the chat.\n")
            elif message.startswith("/msg "):
                text = message[5:].strip()
                if text:
                    broadcast(f"{name}: {text}", sender=conn)
                    print(f"{name}: {text}")
            else:
                conn.sendall(b"Use /msg message to send a chat message.\n")

    except (OSError, socket.timeout):
        pass
    finally:
        with chat_lock:
            old_name = chat_clients.pop(conn, None)
        if old_name:
            broadcast(f"* {old_name} left the chat *")
            print(f"{old_name} left the chat")
        if reader:
            reader.close()
        conn.close()


def chat_server():
    host = "127.0.0.1"
    port = get_port("Chat server port (example 5002): ")
    if port is None:
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(20)
            print(f"Chat server listening on {host}:{port}")
            print("Press Ctrl+C to stop.")

            while True:
                conn, address = server.accept()
                thread = threading.Thread(
                    target=handle_chat_client,
                    args=(conn, address),
                    daemon=True,
                )
                thread.start()
    except KeyboardInterrupt:
        print("\nChat server stopped.")
    except OSError as error:
        print(f"Chat server error: {error}")


def chat_client():
    host = input("Chat server IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = get_port("Chat server port: ")
    if port is None:
        return

    try:
        with socket.create_connection((host, port), timeout=5) as client:
            client.settimeout(None)
            print("Connected to chat.")
            print("Commands: /join, /msg your message, /leave")

            # A separate thread receives messages while you type.
            def receive_messages():
                reader = client.makefile(
                    "r", encoding="utf-8", errors="replace"
                )
                try:
                    for line in reader:
                        print("\n" + line.rstrip() + "\nYou: ", end="", flush=True)
                except OSError:
                    pass

            threading.Thread(
                target=receive_messages, daemon=True
            ).start()

            # Server prompts for the name before regular chat messages.
            # Send name first, then use chat commands.
            name = input("Your name: ").strip()
            client.sendall((name + "\n").encode("utf-8"))

            while True:
                message = input("You: ")
                if message.lower() == "/leave":
                    client.sendall(b"/leave\n")
                    break
                if message == "/join":
                    client.sendall(b"/join\n")
                elif message.startswith("/msg "):
                    client.sendall((message + "\n").encode("utf-8"))
                else:
                    print("Use /msg your message, /join, or /leave.")
    except OSError as error:
        print(f"Chat client error: {error}")


def main():
    while True:
        print("\n====== SOCKET PROGRAMMING TOOL ======")
        print("1. Port Scanner")
        print("2. Banner Grabber")
        print("3. TCP Server")
        print("4. TCP Client")
        print("5. UDP Server")
        print("6. UDP Client")
        print("7. Chat Server")
        print("8. Chat Client")
        print("0. Exit")

        choice = input("Select an option: ").strip()

        actions = {
            "1": port_scanner,
            "2": banner_grabber,
            "3": tcp_server,
            "4": tcp_client,
            "5": udp_server,
            "6": udp_client,
            "7": chat_server,
            "8": chat_client,
        }

        if choice == "0":
            print("Goodbye!")
            break
        elif choice in actions:
            actions[choice]()
        else:
            print("Invalid choice. Select 0-8.")


if __name__ == "__main__":
    main()