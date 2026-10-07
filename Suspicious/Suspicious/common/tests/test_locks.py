from django.core.cache import cache
from django.test import SimpleTestCase

from common.locks import cache_lock


class CacheLockTest(SimpleTestCase):
    def setUp(self):
        cache.delete("lock:t")

    def test_lock_is_exclusive_and_released(self):
        with cache_lock("lock:t"):
            with self.assertRaises(RuntimeError):
                with cache_lock("lock:t", wait=0.3):
                    pass
        with cache_lock("lock:t", wait=0.3):  # free again after the first block
            pass

    def test_released_even_when_the_body_raises(self):
        with self.assertRaises(ValueError):
            with cache_lock("lock:t"):
                raise ValueError("boom")
        with cache_lock("lock:t", wait=0.3):
            pass
