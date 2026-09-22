from __future__ import annotations

from pathlib import Path

import pytest

from code_analyzer.errors import UserError
from code_analyzer.settings import DEFAULT_LOCAL_ENDPOINT, Settings, home, load_settings


def test_missing_file_is_every_default(private_home: Path) -> None:
    settings = load_settings()
    assert settings == Settings()
    assert settings.local_endpoint == DEFAULT_LOCAL_ENDPOINT and settings.review_model == settings.local_model
    assert settings.data_root == private_home / "evaluations" and home() == private_home


def test_nine_settings_parse(tmp_path: Path) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(
        'port = 9000\ndata_root = "~/evals"\n'
        '[local_model]\nendpoint = "http://10.0.0.2:11434/v1"\nname = "qwen"\nreview_name = "qwen-u"\n'
        '[public_model]\nendpoint = "https://api.b.ai/v1"\nname = "glm"\napi_key_env = "B_AI_API_KEY"\n'
        '[analyzers]\ncppcheck = "/opt/cppcheck"\nsplint = ""\n', encoding="utf-8")
    settings = load_settings(path)
    assert settings.port == 9000 and settings.data_root == Path("~/evals").expanduser()
    assert settings.review_model == "qwen-u" and settings.has_public_model
    assert settings.analyzers == {"cppcheck": "/opt/cppcheck"}


@pytest.mark.parametrize("text", [
    "colour = 1\n", "[local_model]\nmodel = \"x\"\n", "port = \"80\"\n", "port = 0\n", "local_model = 3\n",
    "port = true\n", "[analyzers]\nclang = \"x\"\n", "not toml =\n",
])
def test_bad_settings_are_errors(tmp_path: Path, text: str) -> None:
    path = tmp_path / "settings.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(UserError):
        load_settings(path)
