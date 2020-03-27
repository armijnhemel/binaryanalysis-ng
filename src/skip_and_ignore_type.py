
class SkipAndIgnoreType:
    """Kaitai struct Opaque parser that skips and ignores the data. Useful
    for fields of which you do not want to store data. Add the attribute
    ks-opaque-types: true to the meta section of the .ksy file.
    If using opaque types, the kaitai visualizer tools will no longer work."""
    def __init__(self, stream):
        pass

