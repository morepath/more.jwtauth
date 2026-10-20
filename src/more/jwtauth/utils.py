from importlib import import_module
from typing import Any


def import_dotted_path(path: str) -> Any:
    """
    Takes a dotted path to a member name in a module, and returns
    the member after importing it.
    """
    try:
        module_path, member_name = path.rsplit(".", 1)
        module = import_module(module_path)
        return getattr(module, member_name)
    except (ValueError, ImportError, AttributeError) as e:
        raise ImportError(f"Could not import the name: {path}: {e}")


def handler(path: str | None) -> Any | None:
    """
    Returns a handler from a dotted path and None if no path given.
    """
    if path:
        return import_dotted_path(path)
    else:
        return None
