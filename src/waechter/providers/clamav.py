"""Public import facade for the ClamAV provider package."""

from waechter.providers._clamav.provider import ClamAVProvider
from waechter.providers._clamav.models import ClamAVDownloadError

__all__ = ["ClamAVProvider", "ClamAVDownloadError"]
