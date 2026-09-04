import asyncio
import json

import pytest

from passforge.core.enums import PasswordCategory, PasswordStrength
from passforge.core.exceptions import ExportPathError, UnsupportedExportFormatError
from passforge.models.password import GeneratedPassword
from passforge.services.exporter import ResultExporter


def _sample():
    return [
        GeneratedPassword(
            value="Abc123!@",
            category=PasswordCategory.COMPLEX,
            strength=PasswordStrength.STRONG,
            charset_size=94,
        )
    ]


class TestResultExporter:
    def test_exports_json(self, tmp_path):
        out = tmp_path / "out.json"
        exporter = ResultExporter()
        asyncio.run(exporter.export(_sample(), str(out), metadata={"category": "complex"}))
        data = json.loads(out.read_text())
        assert data["count"] == 1
        assert data["results"][0]["value"] == "Abc123!@"

    def test_exports_csv(self, tmp_path):
        out = tmp_path / "out.csv"
        exporter = ResultExporter()
        asyncio.run(exporter.export(_sample(), str(out)))
        content = out.read_text()
        assert "value" in content.splitlines()[0]
        assert "Abc123!@" in content

    def test_unsupported_extension_raises(self, tmp_path):
        out = tmp_path / "out.txt"
        exporter = ResultExporter()
        with pytest.raises(UnsupportedExportFormatError):
            asyncio.run(exporter.export(_sample(), str(out)))

    def test_missing_directory_raises(self, tmp_path):
        out = tmp_path / "missing_dir" / "out.json"
        exporter = ResultExporter()
        with pytest.raises(ExportPathError):
            asyncio.run(exporter.export(_sample(), str(out)))
