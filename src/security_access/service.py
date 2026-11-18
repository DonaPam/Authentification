"""Optional Unix-domain-socket boundary for a service-account deployment.

The interactive shell currently uses the same application API for local use. This
module provides the Linux socket identity primitive used when deploying a separate
service process: the kernel, rather than client input, supplies the peer UID.
"""

from __future__ import annotations

import socket
import struct

from .errors import AuthenticationError


def peer_uid(connection: socket.socket) -> int:
    """Return the connected Linux process UID using SO_PEERCRED."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise AuthenticationError("Unix peer credential authentication requires Linux SO_PEERCRED.")
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", credentials)
    return uid
