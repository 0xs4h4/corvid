"""Detection modules. Importing submodules registers them in the module registry."""

from . import base  # noqa: F401
from .discovery import domain  # noqa: F401
from .credentials import credentials  # noqa: F401
from .acl import acl  # noqa: F401
from .gpo import gpo  # noqa: F401
from .delegation import delegation  # noqa: F401
from .adcs import adcs  # noqa: F401
from .privilege import privesc  # noqa: F401
from .network import network  # noqa: F401
from .infrastructure import infrastructure  # noqa: F401
from .vulnerabilities import vulnerabilities  # noqa: F401
from .persistence import persistence  # noqa: F401
