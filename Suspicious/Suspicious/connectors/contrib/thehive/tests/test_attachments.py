from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from connectors.contrib.thehive.attachments import add_binary_attachment_to_item


class AddBinaryAttachmentToItemTest(SimpleTestCase):
    def _mock_response(self, payload):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = payload
        return resp

    def test_posts_to_plural_attachments_endpoint_with_attachments_field(self):
        resp = self._mock_response({"attachments": [{"_id": "att-1"}]})
        with patch(
            "connectors.contrib.thehive.attachments._session.post", return_value=resp,
        ) as mock_post:
            result = add_binary_attachment_to_item(
                "alert", "~alert-1", "mail.zip", b"zipbytes",
                "https://hive.local", "key123",
            )

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://hive.local/api/v1/alert/~alert-1/attachments")
        self.assertIn("attachments", kwargs["files"])
        self.assertEqual(kwargs["files"]["attachments"], ("mail.zip", b"zipbytes", "application/zip"))
        self.assertEqual(kwargs.get("data"), {"canRename": True})
        self.assertEqual(result, [{"_id": "att-1"}])
