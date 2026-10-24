import re
from io import BytesIO

from PIL import Image

Image.MAX_IMAGE_PIXELS = 20_000_000  # blocks decompression bombs

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
MAX_VARIANTS = 5000
ALLOWED_FORMATS = {"PNG", "JPEG", "GIF", "BMP", "WEBP"}


def validate_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if not DOMAIN_RE.match(d):
        raise ValueError("Invalid domain")
    return d


def load_image_safely(raw: bytes) -> Image.Image:
    img = Image.open(BytesIO(raw))
    img.verify()
    img = Image.open(BytesIO(raw))  # must reopen after verify()
    if img.format not in ALLOWED_FORMATS:
        raise ValueError("Unsupported image type")
    return img


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")
