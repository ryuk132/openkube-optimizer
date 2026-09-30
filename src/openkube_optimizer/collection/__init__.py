"""Kubernetes I/O boundary; importing this package activates no clients or I/O.

Future adapters own SDK/transport objects and immediately project allowlisted
facts into domain records. Collection, projection and ownership are not yet
implemented; do not expose raw SDK types outside this boundary.
"""
