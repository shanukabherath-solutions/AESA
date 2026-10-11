import sqlite3
from collections.abc import Iterator

import pytest

from app import db


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_SECRET_KEY", "test-only-secret-key-for-unit-tests")


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = db.connect()
    yield c
    c.close()
