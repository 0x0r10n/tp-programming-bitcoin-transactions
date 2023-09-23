from typing import (
    Protocol,
    TypeVar,
    runtime_checkable,
)

T = TypeVar("T")


@runtime_checkable
class FieldElement(Protocol):
    def __eq__(self: T, other: T) -> bool:
        ...

    def __ne__(self: T, other: T) -> bool:
        ...

    def __add__(self: T, other: T) -> T:
        ...

    def __sub__(self: T, other: T) -> T:
        ...

    def __mul__(self: T, other: T) -> T:
        ...

    def __pow__(self: T, exponent: int) -> T:
        ...

    def __truediv__(self: T, other: T) -> T:
        ...

    def __rmul__(self: T, coefficient: int) -> T:
        ...


FieldElementT = TypeVar("FieldElementT", bound=FieldElement)
