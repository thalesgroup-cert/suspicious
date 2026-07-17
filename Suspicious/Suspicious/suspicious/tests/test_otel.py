import logging
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from suspicious.otel import TraceIdFilter


class TestTraceIdFilter(SimpleTestCase):

    def _make_record(self):
        return logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello", args=(), exc_info=None,
        )

    def test_zero_trace_when_no_active_span(self):
        mock_span = MagicMock()
        mock_span.get_span_context.return_value = MagicMock(is_valid=False)

        with patch("suspicious.otel.trace") as mock_trace:
            mock_trace.get_current_span.return_value = mock_span
            f = TraceIdFilter()
            record = self._make_record()
            f.filter(record)

        self.assertEqual(record.trace_id, "0" * 32)
        self.assertEqual(record.span_id, "0" * 16)

    def test_real_trace_id_injected(self):
        ctx = MagicMock(is_valid=True, trace_id=0xABCD, span_id=0x1234)
        mock_span = MagicMock()
        mock_span.get_span_context.return_value = ctx

        with patch("suspicious.otel.trace") as mock_trace:
            mock_trace.get_current_span.return_value = mock_span
            f = TraceIdFilter()
            record = self._make_record()
            f.filter(record)

        self.assertEqual(record.trace_id, format(0xABCD, "032x"))
        self.assertEqual(record.span_id, format(0x1234, "016x"))

    def test_filter_always_returns_true(self):
        f = TraceIdFilter()
        record = self._make_record()
        result = f.filter(record)
        self.assertTrue(result)

    def test_filter_graceful_on_import_error(self):
        """If opentelemetry is not installed, filter returns True with zero ids."""
        f = TraceIdFilter()
        record = self._make_record()
        with patch.dict("sys.modules", {"opentelemetry": None}):
            result = f.filter(record)
        self.assertTrue(result)
        self.assertEqual(record.trace_id, "0" * 32)
