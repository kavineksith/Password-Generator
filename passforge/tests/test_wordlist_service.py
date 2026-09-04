from pathlib import Path

import pytest

from passforge.core.exceptions import WordlistFormatError, WordlistNotFoundError
from passforge.services.wordlist_service import WordlistService

FIXTURE = Path(__file__).parent / "fixtures_wordlist.txt"


class TestWordlistService:
    def test_load_returns_words(self):
        import asyncio

        service = WordlistService(str(FIXTURE))
        words = asyncio.run(service.load())
        assert "apple" in words
        assert len(words) == 10

    def test_load_caches_result(self):
        import asyncio

        service = WordlistService(str(FIXTURE))
        first = asyncio.run(service.load())
        second = asyncio.run(service.load())
        assert first is second

    def test_missing_file_raises(self, tmp_path):
        import asyncio

        service = WordlistService(str(tmp_path / "nope.txt"))
        with pytest.raises(WordlistNotFoundError):
            asyncio.run(service.load())

    def test_empty_file_raises_format_error(self, tmp_path):
        import asyncio

        empty = tmp_path / "empty.txt"
        empty.write_text("")
        service = WordlistService(str(empty))
        with pytest.raises(WordlistFormatError):
            asyncio.run(service.load())

    def test_dice_roll_prefixed_format_parses_word_only(self, tmp_path):
        import asyncio

        f = tmp_path / "dice.txt"
        f.write_text("11111\talpha\n22222\tbeta\n")
        service = WordlistService(str(f))
        words = asyncio.run(service.load())
        assert words == ["alpha", "beta"]
