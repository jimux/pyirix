"""Make ``pyirix`` importable however this checkout is named, and register the
``slow`` marker.

The package root IS the repository root (``pyirix/__init__.py``), so normally
the directory holding it is on ``sys.path``.  pytest puts the test file's own
directory there instead, and a git worktree or a clone may hold the repository
under another name, so the package is loaded under the name ``pyirix`` from the
repo root found above this file.
"""
import importlib.util
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_package():
    import pyirix  # noqa: F401  (already installed or on the path)


def _ensure_importable():
    try:
        _load_package()
        return
    except ImportError:
        pass
    spec = importlib.util.spec_from_file_location(
        "pyirix", os.path.join(_REPO_ROOT, "__init__.py"),
        submodule_search_locations=[_REPO_ROOT])
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyirix"] = module
    spec.loader.exec_module(module)


_ensure_importable()


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow: stages a real IRIX dist tree (hundreds of MB), seconds not milliseconds")
