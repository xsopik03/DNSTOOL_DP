from .base import BaseSourceAnalyzer
from .intodns import IntoDnsSourceAnalyzer
from .intodns_ai import IntoDnsAiSourceAnalyzer
from .mxtoolbox import MxToolboxSourceAnalyzer
from .zonemaster import ZonemasterSourceAnalyzer


def build_source_analyzers():
    return {
        "zonemaster": ZonemasterSourceAnalyzer(),
        "intodns_ai": IntoDnsAiSourceAnalyzer(),
        "intodns": IntoDnsSourceAnalyzer(),
        "mxtoolbox": MxToolboxSourceAnalyzer(),
    }


__all__ = ["BaseSourceAnalyzer", "build_source_analyzers"]