"""Pattern inference and candidate ranking.

Confidence for named samples is ``ratio * (1 - 0.55 ** n)``, capped at 0.97
and rounded to two decimals. One agreeing sample is a weak observation (0.45).
Three agreeing samples are strong but not certain (0.83), because companies
mix formats. Structural guesses, which have no names attached, stay at 0.34
so they never outrank a single named match.
"""

from __future__ import annotations

import pytest

from openhunter.errors import InputError
from openhunter.names import split_name
from openhunter.patterns import (
    KnownEmail,
    generate_candidates,
    infer_pattern,
    sample_confidence,
)


def test_confidence_curve_is_honest_about_sample_size() -> None:
    assert sample_confidence(1, 1) == 0.45
    assert sample_confidence(2, 2) == 0.70
    assert sample_confidence(3, 3) == 0.83
    assert sample_confidence(1, 2) == 0.35
    assert sample_confidence(5, 5) == 0.95
    assert sample_confidence(8, 8) == 0.97
    assert sample_confidence(0, 3) == 0.0
    assert sample_confidence(3, 0) == 0.0


def test_split_name_drops_honorifics_suffixes_and_middle_names() -> None:
    assert split_name("Dr. Ada Lovelace") == ("Ada", "Lovelace")
    assert split_name("Ada Lovelace, PhD") == ("Ada", "Lovelace")
    assert split_name("Mary Jane Watson") == ("Mary", "Watson")
    assert split_name("Ada") == ("Ada", None)
    assert split_name("  ") == (None, None)
    assert split_name(None) == (None, None)


def test_infers_first_dot_last_from_unanimous_named_samples() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("ada.lovelace@example.com", "Ada", "Lovelace"),
            KnownEmail("alan.turing@example.com", "Alan", "Turing"),
            KnownEmail("grace.hopper@example.com", "Grace", "Hopper"),
        ],
    )
    assert result.pattern == "first.last"
    assert result.confidence == 0.83
    assert result.sample_count == 3
    assert result.matched_count == 3
    assert result.method == "named"
    assert result.alternates[0].pattern == "first.last"


def test_majority_pattern_wins_and_unmatched_names_lower_confidence() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("alovelace@example.com", "Ada", "Lovelace"),
            KnownEmail("aturing@example.com", "Alan", "Turing"),
            KnownEmail("grace.hopper@example.com", "Grace", "Hopper"),
            KnownEmail("weird@example.com", "Katherine", "Johnson"),
        ],
    )
    assert result.pattern == "flast"
    assert result.matched_count == 2
    assert result.sample_count == 4
    assert result.method == "named"
    # 2/4 * (1 - 0.55**4) = 0.45
    assert result.confidence == 0.45
    votes = {item.pattern: item.matched_count for item in result.alternates}
    assert votes["flast"] == 2
    assert votes["first.last"] == 1


def test_single_named_sample_cannot_look_certain() -> None:
    result = infer_pattern(
        "Example.COM",
        [KnownEmail("Ada.Lovelace+news@example.com", full_name="Ada Lovelace")],
    )
    assert result.domain == "example.com"
    assert result.pattern == "first.last"
    assert result.confidence == 0.45
    assert result.sample_count == 1


def test_duplicate_emails_vote_once() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("ada.lovelace@example.com", "Ada", "Lovelace"),
            KnownEmail("Ada.Lovelace@example.com", "Ada", "Lovelace"),
        ],
    )
    assert result.sample_count == 1
    assert result.confidence == 0.45


def test_ignores_other_domains_roles_and_github_noreply() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("ada.lovelace@other.com", "Ada", "Lovelace"),
            KnownEmail("ada@staff.example.com", "Ada", "Lovelace"),
            KnownEmail("info@example.com", "Info", "Desk"),
            KnownEmail("123+ada@users.noreply.github.com", "Ada", "Lovelace"),
            KnownEmail("ada.lovelace@example.com", "Ada", "Lovelace"),
        ],
    )
    assert result.sample_count == 1
    assert result.pattern == "first.last"


def test_accented_and_particle_names_match_compact_mailbox() -> None:
    accented = infer_pattern(
        "example.com",
        [KnownEmail("jose.garcia@example.com", "José", "García")],
    )
    particle = infer_pattern(
        "example.com",
        [KnownEmail("vincent.vangogh@example.com", "Vincent", "van Gogh")],
    )
    assert accented.pattern == "first.last"
    assert particle.pattern == "first.last"


def test_hyphenated_first_name_matches_either_spelling() -> None:
    compact = infer_pattern(
        "example.com",
        [KnownEmail("annemarie.scott@example.com", "Anne-Marie", "Scott")],
    )
    hyphen = infer_pattern(
        "example.com",
        [KnownEmail("anne-marie.scott@example.com", "Anne-Marie", "Scott")],
    )
    assert compact.pattern == "first.last"
    assert hyphen.pattern == "first.last"


def test_single_letter_first_name_tie_prefers_more_common_pattern() -> None:
    # "ali" is both {first}{last} and {f}{last} when the first name is one letter.
    # flast is the more common corporate pattern, so it wins the tie.
    result = infer_pattern(
        "example.com",
        [KnownEmail("ali@example.com", "A", "Li")],
    )
    assert result.pattern == "flast"
    tied = {item.pattern for item in result.alternates if item.matched_count == 1}
    assert "flast" in tied
    assert "firstlast" in tied


def test_named_samples_that_match_nothing_do_not_fall_through_to_structure() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("alex.chen@example.com", "Robert", "Smith"),
            KnownEmail("sam.patel@example.com", "Robert", "Jones"),
            KnownEmail("jordan.lee@example.com", "Robert", "Brown"),
        ],
    )
    assert result.pattern is None
    assert result.method == "none"
    assert result.sample_count == 3
    assert result.matched_count == 0
    assert result.confidence == 0.0


def test_structural_guess_when_no_names_and_locals_agree() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("alex.chen@example.com"),
            KnownEmail("sam.patel@example.com"),
            KnownEmail("jordan.lee@example.com"),
            KnownEmail("solo@example.com"),
        ],
    )
    assert result.pattern == "first.last"
    assert result.method == "structural"
    assert result.confidence == 0.34
    assert result.matched_count == 3
    assert any("structural" in note.lower() for note in result.notes)


def test_mixed_structure_without_names_does_not_invent_a_pattern() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("alex.chen@example.com"),
            KnownEmail("sam.patel@example.com"),
            KnownEmail("solo@example.com"),
        ],
    )
    assert result.pattern is None
    assert result.method == "none"


def test_empty_input() -> None:
    result = infer_pattern("example.com", [])
    assert result.pattern is None
    assert result.confidence == 0.0
    assert result.sample_count == 0
    assert result.method == "none"


def test_f_dot_last_pattern() -> None:
    result = infer_pattern(
        "example.com",
        [
            KnownEmail("a.lovelace@example.com", "Ada", "Lovelace"),
            KnownEmail("a.turing@example.com", "Alan", "Turing"),
        ],
    )
    assert result.pattern == "f.last"


def test_finder_ranks_common_patterns_without_evidence() -> None:
    candidates = generate_candidates("Grace", "Hopper", "example.com")
    assert [item.pattern for item in candidates[:3]] == ["first.last", "flast", "first"]
    assert candidates[0].email == "grace.hopper@example.com"
    assert candidates[0].rank == 1
    assert candidates[0].score > candidates[1].score
    assert len(candidates) == 8
    assert [item.rank for item in candidates] == list(range(1, 9))


def test_finder_puts_inferred_pattern_first() -> None:
    inference = infer_pattern(
        "example.com",
        [
            KnownEmail("ada.lovelace@example.com", "Ada", "Lovelace"),
            KnownEmail("alan.turing@example.com", "Alan", "Turing"),
            KnownEmail("grace.hopper@example.com", "Grace", "Hopper"),
        ],
    )
    candidates = generate_candidates("Grace", "Hopper", "example.com", inference)
    assert candidates[0].email == "grace.hopper@example.com"
    assert candidates[0].pattern == "first.last"
    assert candidates[0].score > candidates[1].score
    assert "inferred" in candidates[0].reason


def test_finder_emits_hyphenated_and_particle_variants() -> None:
    hyphenated = {item.email for item in generate_candidates("Anne-Marie", "Scott", "example.com")}
    assert "annemarie.scott@example.com" in hyphenated
    assert "anne-marie.scott@example.com" in hyphenated
    particle = {item.email for item in generate_candidates("Vincent", "van Gogh", "example.com")}
    assert "vincent.vangogh@example.com" in particle
    assert "vincent.gogh@example.com" in particle


def test_finder_normalizes_a_pasted_url_and_rejects_garbage() -> None:
    candidates = generate_candidates("Grace", "Hopper", "https://www.example.com/team")
    assert candidates[0].email.endswith("@example.com")
    with pytest.raises(InputError):
        generate_candidates("", "Hopper", "example.com")
    with pytest.raises(InputError):
        generate_candidates("Grace", "", "example.com")
    with pytest.raises(InputError):
        generate_candidates("Grace", "Hopper", "localhost")
    with pytest.raises(InputError):
        generate_candidates("Grace", "Hopper", "127.0.0.1")
