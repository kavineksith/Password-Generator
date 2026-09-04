"""Async loader/streamer for the EFF large wordlist used in passphrases."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncGenerator, List, Optional

import aiofiles

from passforge.core.exceptions import (
    WordlistFormatError,
    WordlistNotFoundError,
    WordlistReadError,
)


class WordlistService:
    """Loads and caches the EFF wordlist asynchronously."""

    def __init__(self, wordlist_path: str = "eff_large_wordlist.txt") -> None:
        self.wordlist_path = Path(wordlist_path)
        self._cache: Optional[List[str]] = None

    async def _stream_lines(self) -> AsyncGenerator[str, None]:
        """Yield non-empty, stripped words one at a time from the file.

        EFF wordlist files are formatted as ``<dice-roll>\\t<word>`` lines;
        only the word column is yielded.
        """
        if not self.wordlist_path.exists():
            raise WordlistNotFoundError(
                f"Wordlist file not found: {self.wordlist_path}",
                context={"path": str(self.wordlist_path)},
            )
        try:
            async with aiofiles.open(self.wordlist_path, mode="r", encoding="utf-8") as handle:
                async for line in handle:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    # Support both "word" and "11111\tword" formats.
                    parts = stripped.split()
                    word = parts[-1]
                    yield word
        except OSError as exc:
            raise WordlistReadError(
                f"Failed to read wordlist: {exc}",
                context={"path": str(self.wordlist_path)},
            ) from exc

    async def load(self, force_reload: bool = False) -> List[str]:
        """Load (and cache) the full wordlist as a list of words."""
        if self._cache is not None and not force_reload:
            return self._cache

        words = [word async for word in self._stream_lines()]

        if not words:
            raise WordlistFormatError(
                "Wordlist file is empty or contains no usable words",
                context={"path": str(self.wordlist_path)},
            )

        self._cache = words
        return self._cache

    def __repr__(self) -> str:
        size = len(self._cache) if self._cache is not None else "unloaded"
        return f"WordlistService(path={str(self.wordlist_path)!r}, words={size})"
