import re
from typing import Any

_PATTERN = re.compile(r"(?<!^)(?=[A-Z])")


def snake_to_camel(name: str, overrides: dict[str, str] | None = None) -> str:
    """
    Converts name from snake case to camel case. If name is in overrides, then return
    the overridden value instead.

    Examples:

    assert snake_to_camel("foo_bar_baz") == "fooBarBaz"
    assert snake_to_camel("foo_bar_baz", {"foo_bar_baz": "fooBARBaz}) == "fooBARBaz"
    """
    if overrides is not None and name in overrides:
        return overrides[name]

    words = [word.title() for word in name.split("_")]
    words[0] = words[0].lower()
    return "".join(words)


def camel_to_snake(s: str) -> str:
    """
    Converts `s` from camel case to snake case.
    """
    return _PATTERN.sub("_", s).lower()


def convert_dict_keys_to_snake_case(d: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively converts all keys in `d` from camel case to snake case.
    """
    return {
        camel_to_snake(k): v
        if not isinstance(v, dict)
        else convert_dict_keys_to_snake_case(v)
        for k, v in d.items()
    }
