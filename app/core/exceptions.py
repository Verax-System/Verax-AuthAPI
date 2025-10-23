# auth_api/app/core/exceptions.py
from datetime import datetime


class AccountLockedException(Exception):
    """Exceção levantada quando uma tentativa de login é feita em uma conta bloqueada."""

    def __init__(
        self, message="Account is locked", locked_until: datetime | None = None
    ):
        self.message = message
        self.locked_until = locked_until
        super().__init__(self.message)
