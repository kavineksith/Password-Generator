"""Async export of generation results to JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from passforge.core.enums import LogEventType
from passforge.core.exceptions import (
    ExportPathError,
    ExportWriteError,
    UnsupportedExportFormatError,
)
from passforge.core.logger import log_event
from passforge.models.password import GeneratedPassword

_SUPPORTED_FORMATS = {".json", ".csv"}


class ResultExporter:
    """Persists generated password results to disk asynchronously."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger("passforge")

    async def export(
        self,
        results: List[GeneratedPassword],
        output_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        path = Path(output_path)
        suffix = path.suffix.lower()

        if suffix not in _SUPPORTED_FORMATS:
            raise UnsupportedExportFormatError(
                f"Unsupported export extension '{suffix}'. Use .json or .csv",
                context={"path": str(path), "supported": sorted(_SUPPORTED_FORMATS)},
            )

        if path.parent and not path.parent.exists():
            raise ExportPathError(
                f"Destination directory does not exist: {path.parent}",
                context={"path": str(path)},
            )

        try:
            if suffix == ".json":
                await self._export_json(path, results, metadata or {})
            else:
                await self._export_csv(path, results)
        except OSError as exc:
            log_event(
                self.logger,
                logging.ERROR,
                "Export failed",
                event_type=str(LogEventType.EXPORT_FAILURE),
                context={"path": str(path), "error": str(exc)},
            )
            raise ExportWriteError(
                f"Failed to write export file: {exc}", context={"path": str(path)}
            ) from exc

        log_event(
            self.logger,
            logging.INFO,
            "Export succeeded",
            event_type=str(LogEventType.EXPORT_SUCCESS),
            context={"path": str(path), "count": len(results)},
        )

    async def _export_json(
        self, path: Path, results: List[GeneratedPassword], metadata: Dict[str, Any]
    ) -> None:
        payload = {
            **metadata,
            "count": len(results),
            "results": [r.to_dict() for r in results],
        }
        async with aiofiles.open(path, mode="w", encoding="utf-8") as handle:
            await handle.write(json.dumps(payload, indent=2))

    async def _export_csv(self, path: Path, results: List[GeneratedPassword]) -> None:
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer, fieldnames=["value", "category", "strength", "length", "entropy_bits", "generated_at"]
        )
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_dict())

        async with aiofiles.open(path, mode="w", encoding="utf-8", newline="") as handle:
            await handle.write(buffer.getvalue())

    def __repr__(self) -> str:
        return "ResultExporter()"
