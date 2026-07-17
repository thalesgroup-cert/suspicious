"""Reusable Django model mixins."""


class AllowListableMixin:
    """Adds ``update_allow_listed()`` to score-bearing IOC/file models.

    Marks the instance as safe/allow-listed (score 0, confidence 100,
    level ``SAFE-ALLOW_LISTED``). Models with non-default score field names
    (e.g. files use ``file_*`` instead of ``ioc_*``) override
    :attr:`allowlist_score_fields`.
    """

    allowlist_score_fields: tuple[str, str, str] = (
        "ioc_score", "ioc_confidence", "ioc_level",
    )

    def update_allow_listed(self):
        score, confidence, level = self.allowlist_score_fields
        setattr(self, score, 0)
        setattr(self, confidence, 100)
        setattr(self, level, "SAFE-ALLOW_LISTED")
        self.save(update_fields=list(self.allowlist_score_fields))
