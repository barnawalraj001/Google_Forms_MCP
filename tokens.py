import json
from pathlib import Path
from tempfile import NamedTemporaryFile

TOKEN_FILE = Path("tokens.json")


def load_tokens() -> dict:
    """
    Load all stored OAuth tokens.
    Structure:
    {
      "user_id": {
        "token": "...",
        "refresh_token": "..."
      }
    }
    """
    if not TOKEN_FILE.exists():
        return {}

    try:
        return json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Corrupted file fallback
        return {}


def save_tokens(tokens: dict) -> None:
    """
    Safely write tokens to disk using atomic replace.
    Prevents file corruption during concurrent writes.
    """
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)

    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=TOKEN_FILE.parent
    ) as tmp:
        json.dump(tokens, tmp, indent=2, ensure_ascii=False)
        temp_name = tmp.name

    Path(temp_name).replace(TOKEN_FILE)
