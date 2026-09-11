from importlib.metadata import PackageNotFoundError, version

try:
    # Read the version from installed package metadata rather than restating it
    # here, where it had drifted to 0.1.1 while pyproject.toml said 0.7.0.
    __version__ = version("duckduckgo-mcp-server")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"
