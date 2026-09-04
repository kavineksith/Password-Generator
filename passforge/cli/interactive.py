"""Interactive REPL wizard mode with readline history support."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

try:
    import readline  # noqa: F401  (POSIX only; enables arrow-key history)
except ImportError:  # pragma: no cover - Windows fallback
    readline = None

from passforge.core.enums import PasswordCategory, PasswordStrength
from passforge.core.exceptions import InteractiveAbortError, PassforgeError
from passforge.models.policy import PasswordPolicy
from passforge.services.exporter import ResultExporter
from passforge.services.generator import PasswordGeneratorService
from passforge.services.wordlist_service import WordlistService

HISTORY_FILE = Path.home() / ".passforge_history"

_CATEGORY_MAP = {
    "1": PasswordCategory.ALPHANUMERIC,
    "2": PasswordCategory.COMPLEX,
    "3": PasswordCategory.PASSPHRASE,
}
_STRENGTH_MAP = {
    "1": PasswordStrength.BASIC,
    "2": PasswordStrength.STRONG,
    "3": PasswordStrength.PARANOID,
}


def _load_history() -> None:
    if readline and HISTORY_FILE.exists():
        try:
            readline.read_history_file(HISTORY_FILE)
        except OSError:
            pass


def _save_history() -> None:
    if readline:
        try:
            readline.write_history_file(HISTORY_FILE)
        except OSError:
            pass


def _prompt(message: str) -> str:
    try:
        return input(message).strip()
    except EOFError as exc:
        raise InteractiveAbortError("Input stream closed") from exc


async def run_interactive(logger: logging.Logger) -> int:
    """Run the interactive generation wizard. Returns a process exit code."""
    _load_history()
    try:
        print("passforge -- Interactive Password Generator")
        print("=" * 44)
        print("\nCategories:\n 1. Alphanumeric\n 2. Complex\n 3. Passphrase")
        category = _CATEGORY_MAP.get(_prompt("\nSelect category (1-3): "))
        if category is None:
            raise InteractiveAbortError("Invalid category selection")

        prompt_label = "Enter number of words: " if category == PasswordCategory.PASSPHRASE else "Enter password length: "
        raw_length = _prompt(prompt_label)
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise InteractiveAbortError("Length must be an integer") from exc

        print("\nStrength:\n 1. Basic\n 2. Strong (recommended)\n 3. Paranoid")
        strength = _STRENGTH_MAP.get(_prompt("\nSelect strength (1-3): "))
        if strength is None:
            raise InteractiveAbortError("Invalid strength selection")

        raw_count = _prompt("\nHow many to generate? [1]: ") or "1"
        try:
            count = int(raw_count)
        except ValueError as exc:
            raise InteractiveAbortError("Count must be an integer") from exc

        policy = PasswordPolicy()
        service = PasswordGeneratorService(
            policy=policy, wordlist_service=WordlistService(), logger=logger
        )

        if count == 1:
            results = [await service.generate_one(length, category, strength)]
        else:
            results = await service.generate_many(count, length, category, strength)

        print("\nGenerated:")
        for r in results:
            print(f"  {r.value}   (entropy ~{r.entropy_bits:.1f} bits)")

        if _prompt("\nSave to file? (y/n): ").lower() == "y":
            output_path = _prompt("Enter output filename (.json or .csv): ")
            exporter = ResultExporter(logger=logger)
            await exporter.export(
                results,
                output_path,
                metadata={"category": str(category), "strength": str(strength), "length": length},
            )
            print(f"Saved to {output_path}")

        return 0

    except InteractiveAbortError as exc:
        print(f"\nCancelled: {exc.message}")
        return 0
    except PassforgeError as exc:
        print(f"\nError [{exc.error_code}]: {exc.message}")
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 0
    finally:
        _save_history()
