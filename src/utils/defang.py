import re


def defang_all(value) -> str:
    """Neutralise every URL, domain and email marker so nothing is clickable."""
    text = re.sub(r"(?i)http", "hxxp", str(value))
    return text.replace(".", "[.]").replace("@", "[@]")