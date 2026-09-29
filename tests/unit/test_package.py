"""Smoke test for the installed package and its distribution metadata."""

from importlib.metadata import distribution

import openkube_optimizer


def test_installed_package() -> None:
    installed = distribution("openkube-optimizer")

    assert openkube_optimizer.__name__ == "openkube_optimizer"
    assert installed.metadata["Name"] == "openkube-optimizer"
    assert installed.version == "0.1.0.dev0"
