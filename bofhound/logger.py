import logging
from rich.logging import RichHandler

class ColorScheme:
    domain = "[green]"
    user = "[sea_green3]"
    computer = "[red1]"
    group = "[gold1]"
    pki = "[medium_purple1]"
    pki_template = "[medium_purple2]"
    schema = "[deep_sky_blue1]"
    ou = "[dark_orange]"
    gpo = "[purple]"

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(omit_repeated_times=False, show_path=False, keywords=[])]
)

#logging.getLogger("rich")