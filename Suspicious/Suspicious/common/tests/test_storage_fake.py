from django.test import SimpleTestCase

from common.storage import base
from common.storage.base import StoreError
from common.storage.fake import FakeObjectStore
from common.tests.storage_contract import StoreContract


class FakeStoreContractTest(StoreContract, SimpleTestCase):
    def make_store(self):
        return FakeObjectStore(capabilities={base.FREE_FORM_BUCKET_TAGS})

    def test_unknown_error_code_rejected(self):
        with self.assertRaises(ValueError):
            StoreError("bogus")
