"""Extend MockMemcacheClient and add ``gets`` and ``cas``."""
import time

from pymemcache.exceptions import MemcacheIllegalInputError
from pymemcache.test.utils import MockMemcacheClient


class CasMockMemcacheClient(MockMemcacheClient):
    """Extend MockMemcacheClient and add ``gets`` and ``cas``.

    Haven't bothered trying to contribute these upstream yet because
    https://github.com/pinterest/pymemcache seems largely abandoned,
    hasn't responded to issues or PRs in months/years.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._cas_ids = {}  # Store CAS tokens for keys

    def clear(self):
        super().clear()
        self._cas_ids.clear()

    def set(self, key, value, expire=0, noreply=True, flags=None):
        ret = super().set(key, value, expire=expire, noreply=noreply, flags=flags)
        self._cas_ids[key] = str(time.time_ns()).encode()
        return ret

    def stats(self, *kwargs):
        return {
            **super().stats(*kwargs),
            'cas_enabled': True,
        }

    def gets(self, key, default=None, cas_default=None):
        """Retrieves a key's value and its CAS token.

        Args:
            key: The key to retrieve
            default: Value to return if key not found
            cas_default: CAS token value to return if key not found

        Returns:
            A tuple of (value, bytes cas_token)
        """
        not_found = []

        value = self.get(key, default=not_found)
        if value is not_found:
            return default, cas_default

        cas_token = self._cas_ids.setdefault(key, str(time.time_ns()).encode())
        return value, cas_token

    def cas(self, key, value, cas_token, noreply=False, **kwargs):
        """Compare-and-swap implementation.

        Checks that the CAS token matches the current one before setting the value.

        Args:
            key (str): The key to update
            value: The new value to set
            cas_token (str): The CAS token to check against
            noreply (boolean): whether to wait for the server's response
            kwargs: passed through to :meth:`set`

        Returns:
            If noreply is True, always returns True
            If key doesn't exist, returns None
            If CAS value doesn't match, returns False
            If CAS value matches (operation succeeded), returns True
        """
        if not isinstance(cas_token, (int, str, bytes)):
            raise MemcacheIllegalInputError(f'cas must be integer, string, or bytes, got bad value: {cas_token}')

        key = self.check_key(key)


        if key not in self._contents:
            return self.set(key, value, noreply=noreply, **kwargs)
            return True if noreply else None

        elif self._cas_ids.get(key) != cas_token:
            return True if noreply else False

        return self.set(key, value, noreply=noreply, **kwargs)
