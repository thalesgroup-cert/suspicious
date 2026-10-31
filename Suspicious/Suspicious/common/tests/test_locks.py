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
        self.assertIsNone(cache.get("lock:t"))
        with cache_lock("lock:t", wait=0.3):  # free again after the first block
            pass

    def test_released_even_when_the_body_raises(self):
        with self.assertRaises(ValueError):
            with cache_lock("lock:t"):
                raise ValueError("boom")
        with cache_lock("lock:t", wait=0.3):
            pass

    def test_an_expired_holder_does_not_release_the_next_holder_s_lock(self):
        with cache_lock("lock:t", ttl=60):
            cache.delete("lock:t")  # the TTL ran out while the body was still running
            with cache_lock("lock:t", wait=0.3):
                pass
            cache.add("lock:t", "next-holder", timeout=60)  # another worker holds it now
        self.assertEqual(cache.get("lock:t"), "next-holder")
