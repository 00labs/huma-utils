import pydantic

from huma_utils import string_utils


class Model(pydantic.BaseModel):
    class Config:
        validate_assignment = True
        arbitrary_types_allowed = True
        anystr_strip_whitespace = True
        allow_population_by_field_name = True
        underscore_attrs_are_private = True


class CamelCaseAliased(Model):
    class Config(Model.Config):
        alias_generator = string_utils.snake_to_camel
