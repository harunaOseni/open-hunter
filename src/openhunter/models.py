"""People discovered from public sources, and the merge rule across sources."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum


@dataclass(frozen=True)
class Person:
    name: str | None
    first_name: str | None
    last_name: str | None
    role: str | None
    email: str | None
    source: str
    source_url: str
    confidence: float
    notes: tuple[str, ...] = ()
    is_role: bool = False


def merge_people(people: list[Person]) -> list[Person]:
    """Keep the highest-confidence record per email, and drop a nameless duplicate."""
    best: dict[str, Person] = {}
    order: list[str] = []
    for person in people:
        if person.email:
            key = f"email:{person.email.lower()}"
        elif person.name:
            key = f"name:{person.name.lower()}"
        else:
            key = f"url:{person.source_url}"
        if key not in best:
            best[key] = person
            order.append(key)
            continue
        best[key] = _prefer(best[key], person)
    names_with_email = {(person.name or "").lower() for person in best.values() if person.email and person.name}
    merged: list[Person] = []
    for key in order:
        person = best[key]
        if person.email is None and person.name and person.name.lower() in names_with_email:
            continue
        merged.append(person)
    merged.sort(key=lambda person: (-person.confidence, (person.name or person.email or "").lower()))
    return merged


def to_plain(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: to_plain(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    return value


def _prefer(current: Person, incoming: Person) -> Person:
    primary, secondary = (current, incoming) if current.confidence >= incoming.confidence else (incoming, current)
    notes = tuple(dict.fromkeys((*primary.notes, *secondary.notes)))
    email = (primary.email or secondary.email or "").lower() or None
    name, first_name, last_name = _name_fields(primary, secondary)
    return Person(
        name=name,
        first_name=first_name,
        last_name=last_name,
        role=primary.role or secondary.role,
        email=email,
        source=primary.source,
        source_url=primary.source_url,
        confidence=max(current.confidence, incoming.confidence),
        notes=notes,
        is_role=current.is_role or incoming.is_role,
    )


def _name_fields(primary: Person, secondary: Person) -> tuple[str | None, str | None, str | None]:
    """Prefer a given name plus surname over a login, even from the lower-confidence record.

    A commit often stores the GitHub login in the author name while the public
    profile stores "First Last". The commit stays the source of the address;
    the profile supplies the name that pattern inference can use.
    """
    primary_full = bool(primary.first_name and primary.last_name)
    secondary_full = bool(secondary.first_name and secondary.last_name)
    chosen = secondary if secondary_full and not primary_full else primary
    other = primary if chosen is secondary else secondary
    return (
        chosen.name or other.name,
        chosen.first_name or other.first_name,
        chosen.last_name or other.last_name,
    )
