"""Shared helpers — domain normalization and friends.

Lives in its own mixin so every tool family that needs URL/domain cleanup
can pull it in without duplicating the regex.
"""


class DomainNormalizerMixin:
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Strip scheme/path/query so we get a bare 'host[:port]' string."""
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].split("?")[0]
