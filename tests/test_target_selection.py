"""A removal argument is a name first and an id only as a fallback (D79).

The two readings disagree exactly when a target carries a digit only name, so
that case is the one that pins the order down.
"""

import pytest

from models.managers import TargetRepository
from scanners.target_search import TargetSelection, UnknownTargetError
from tests.conftest import MemoryDatabase

_DIGIT_NAME = "2"
_OTHER_NAME = "ana"
_MISSING_NAME = "maria"


class SelectionLab:
    """Targets stored in one table, read back the way `target remove` reads them."""

    def __init__(self, database: MemoryDatabase) -> None:
        self.database = database

    def target(self, name: str) -> int:
        """One registered target, and its id in the table."""
        return TargetRepository(self.database).resolve(name).id

    def id_of(self, argument: str) -> int:
        """The id the removal would use for that argument."""
        return TargetSelection(TargetRepository(self.database)).id_of(argument)


@pytest.fixture
def selection_lab(database: MemoryDatabase) -> SelectionLab:
    return SelectionLab(database)


def test_a_digit_name_wins_over_the_id_it_looks_like(selection_lab: SelectionLab) -> None:
    named = selection_lab.target(_DIGIT_NAME)
    other = selection_lab.target(_OTHER_NAME)

    assert named != other
    assert selection_lab.id_of(_DIGIT_NAME) == named


def test_a_number_that_names_nothing_is_the_id(selection_lab: SelectionLab) -> None:
    selection_lab.target(_OTHER_NAME)
    numbered = selection_lab.target(_MISSING_NAME)

    assert selection_lab.id_of(str(numbered)) == numbered


def test_a_number_no_target_holds_is_refused(selection_lab: SelectionLab) -> None:
    selection_lab.target(_OTHER_NAME)
    selection_lab.target(_MISSING_NAME)

    with pytest.raises(UnknownTargetError):
        selection_lab.id_of("99")


def test_a_word_no_target_carries_is_refused(selection_lab: SelectionLab) -> None:
    selection_lab.target(_OTHER_NAME)

    with pytest.raises(UnknownTargetError):
        selection_lab.id_of(_MISSING_NAME)
