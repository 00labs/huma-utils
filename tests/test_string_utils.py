import pytest

from huma_utils import string_utils


def describe_snake_to_camel() -> None:
    @pytest.mark.parametrize(
        "input_, expected",
        [
            ("", ""),
            ("foo", "foo"),
            ("foobar", "foobar"),
            ("foo_bar_baz", "fooBarBaz"),
            ("_foo_bar_baz", "FooBarBaz"),  # note this behaviour
        ],
    )
    def it_converts_snake_case_to_camel_case(input_: str, expected: str) -> None:
        assert string_utils.snake_to_camel(input_) == expected

    def with_overrides() -> None:
        def it_returns_the_overriden_value() -> None:
            assert (
                string_utils.snake_to_camel("foo_bar_baz", {"foo_bar_baz": "fooBARBaz"})
                == "fooBARBaz"
            )


def describe_camel_to_snake() -> None:
    @pytest.mark.parametrize(
        "input_, expected",
        [
            ("", ""),
            ("foo", "foo"),
            ("foobar", "foobar"),
            ("fooBarBaz", "foo_bar_baz"),
        ],
    )
    def it_converts_snake_case_to_camel_case(input_: str, expected: str) -> None:
        assert string_utils.camel_to_snake(input_) == expected


def convert_dict_keys_to_snake_case() -> None:
    @pytest.mark.parametrize(
        "input_, expected",
        [
            ({}, {}),
            ({}, {}),
            (
                {
                    "foo": "foo",
                    "barBaz": "barBaz",
                    "qux": {"quuxCorge": "quuxCorge", "graultGarply": "graultGarply"},
                },
                {
                    "foo": "foo",
                    "bar_baz": "barBaz",
                    "qux": {"quux_corge": "quuxCorge", "grault_garply": "graultGarply"},
                },
            ),
        ],
    )
    def it_converts_snake_case_to_camel_case(input_: str, expected: str) -> None:
        assert string_utils.camel_to_snake(input_) == expected
