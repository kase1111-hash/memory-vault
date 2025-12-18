import socket
import json
import os

SOCKET_PATH = os.path.expanduser("~/.agent-os/api/boundary.sock")  # Standard Agent-OS path

def check_recall(memory_class: int) -> tuple[bool, str]:
    """
    Query the boundary-daemon via Unix socket for recall permission.
    Returns (permitted: bool, reason: str)
    """
    request = {
        "command": "check_recall",
        "params": {"memory_class": memory_class}
    }

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(SOCKET_PATH)
            s.sendall(json.dumps(request).encode('utf-8') + b'\n')
            response_data = s.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            permitted = response.get("permitted", False)
            reason = response.get("reason", "No reason provided")
            return permitted, reason
    except FileNotFoundError:
        return False, "Boundary daemon socket not found (offline/airgap mode?)"
    except ConnectionRefusedError:
        return False, "Boundary daemon not running"
    except socket.timeout:
        return False, "Boundary daemon timeout"
    except Exception as e:
        return False, f"Boundary daemon error: {str(e)}"
