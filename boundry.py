import socket
import json

SOCKET_PATH = "api/boundary.sock"  # Relative path; configure to absolute in production (e.g., /run/boundary.sock)

def check_recall(memory_class: int) -> tuple[bool, str]:
    """
    Query the boundary-daemon via Unix socket for recall permission.
    Returns (permitted: bool, reason: str)
    """
    request = {
        "command": "check_recall",
        "params": {"memory_class": memory_class}
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        try:
            s.connect(SOCKET_PATH)
            s.sendall(json.dumps(request).encode('utf-8'))
            response_data = s.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            return response.get("permitted", False), response.get("reason", "Permission denied by boundary-daemon")
        except Exception as e:
            return False, f"Boundary daemon connection failed: {str(e)}"
