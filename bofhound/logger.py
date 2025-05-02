import logging
from rich.logging import RichHandler

class ColorScheme:
    domain = "[green]"
    user = "[sea_green3]"
    computer = "[red1]"
    group = "[gold1]"
    enterpriseca = "[medium_purple1]"
    aiaca = "[medium_purple2]"
    rootca = "[medium_purple3]"
    certtemplate = "[bright_magenta]"
    schema = "[deep_sky_blue1]"
    ou = "[dark_orange]"
    containers = "[orange]"
    gpo = "[purple]"

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

FORMAT = "%(message)s"
logger = logging.getLogger("bofhound")

handler = RichHandler(omit_repeated_times=False, show_path=False, keywords=[])
handler.setFormatter(logging.Formatter(FORMAT, datefmt="[%X]"))
logger.addHandler(handler)

logger.propagate = False
