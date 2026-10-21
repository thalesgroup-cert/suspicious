import os
import unittest
from unittest import mock

from django.core.exceptions import ImproperlyConfigured

from suspicious import service_urls
from suspicious.service_urls import redis_url, service_secret


class RedisUrlTests(unittest.TestCase):
    def test_no_password_has_no_auth_segment(self):
        self.assertEqual(redis_url("redis_cache", ""), "redis://redis_cache:6379/0")

    def test_password_is_percent_encoded(self):
        self.assertEqual(
            redis_url("h", "p@ss/w:rd#1"), "redis://:p%40ss%2Fw%3Ard%231@h:6379/0"
        )

    def test_round_trips_through_redis_py_and_kombu(self):
        from kombu.utils.url import parse_url
        from redis.connection import parse_url as redis_parse

        url = redis_url("h", "p@ss/w:rd#1")
        self.assertEqual(redis_parse(url)["password"], "p@ss/w:rd#1")
        self.assertEqual(parse_url(url)["password"], "p@ss/w:rd#1")


class ServiceSecretTests(unittest.TestCase):
    def test_env_wins_over_settings(self):
        with mock.patch.dict(os.environ, {"X_PW": "fromenv"}), \
             mock.patch.object(service_urls, "get_secret", return_value="fromjson"):
            self.assertEqual(service_secret("X_PW", "redis.x", required=True), "fromenv")

    def test_falls_back_to_get_secret(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(service_urls, "get_secret", return_value="fromjson"):
            self.assertEqual(service_secret("X_PW", "redis.x", required=True), "fromjson")

    def test_required_and_missing_raises_naming_the_variable(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(service_urls, "get_secret", return_value=""):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                service_secret("X_PW", "redis.x", required=True)
        self.assertIn("X_PW", str(ctx.exception))
        self.assertIn("make db-auth-migrate", str(ctx.exception))

    def test_not_required_and_missing_returns_empty(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(service_urls, "get_secret", return_value=None):
            self.assertEqual(service_secret("X_PW", "redis.x", required=False), "")
