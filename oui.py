"""
OUI vendor lookup via mac-vendor-lookup package (pip install mac-vendor-lookup).
Falls back to '' gracefully if the package is missing or the OUI is unknown.
"""
_lookup = None


def vendor_for_mac(mac: str) -> str:
    """Return vendor name for a MAC address string, or '' if unknown."""
    if not mac:
        return ''
    global _lookup
    try:
        if _lookup is None:
            from mac_vendor_lookup import MacLookup
            _lookup = MacLookup()
        result = _lookup.lookup(mac)
        return result or ''
    except Exception:
        return ''
