import socket

def test_traversal():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', 8080))
        # Try to access /etc/passwd (assuming unix-like system as per prompt context)
        # We need to go up enough levels.
        request = "GET /../../../../../../../../../../etc/passwd HTTP/1.0\n\n"
        s.sendall(request.encode())
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
            
        s.close()
        
        response_str = response.decode(errors='ignore')
        if "root:" in response_str:
            print("VULNERABILITY CONFIRMED: Successfully read /etc/passwd")
            # print(response_str[:200]) # Print first few lines
        elif "404 Not Found" in response_str:
            print("SAFE: File not found (or blocked)")
        else:
            print(f"Unknown response: {response_str[:50]}...")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_traversal()
