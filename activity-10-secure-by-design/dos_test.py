import socket
import time
import threading
import sys

def hold_connection():
    try:
        print("Client 1: Connecting...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', 8080))
        print("Client 1: Connected. Holding connection for 5 seconds...")
        time.sleep(5)
        s.close()
        print("Client 1: Connection closed.")
    except Exception as e:
        print(f"Client 1 Error: {e}")

def try_connect():
    time.sleep(1) # Wait for client 1 to connect
    try:
        print("Client 2: Connecting...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2) # Timeout quickly if blocked
        s.connect(('localhost', 8080))
        print("Client 2: Connected. Sending request...")
        s.sendall(b"GET /index.html HTTP/1.0\n\n")
        print("Client 2: Request sent. Waiting for response...")
        data = s.recv(1024)
        if data:
            print("Client 2: Received response!")
        else:
            print("Client 2: No response received.")
        s.close()
    except socket.timeout:
        print("Client 2 Error: Timed out waiting for response (BLOCKED)")
    except Exception as e:
        print(f"Client 2 Error: {e}")

if __name__ == "__main__":
    t1 = threading.Thread(target=hold_connection)
    t2 = threading.Thread(target=try_connect)
    
    t1.start()
    t2.start()
    
    t1.join()
    t2.join()
