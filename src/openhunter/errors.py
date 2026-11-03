"""User-facing errors. Messages are safe to show in the CLI and to an MCP client."""


class InputError(ValueError):
    """The request itself is unusable. Nothing was fetched or probed."""


class OpenHunterError(RuntimeError):
    """A dependency failed in a way the caller can retry or rephrase."""
