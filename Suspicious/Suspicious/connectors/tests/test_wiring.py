from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case


def make_user():
    return get_user_model().objects.create_user(
        username="rep", email="r@e.c", password="x"
    )


class CaseCreatedSignalTest(TestCase):
    def test_case_creation_emits_event(self):
        user = make_user()
        with mock.patch("connectors.signals.emit") as emit_mock:
            case = Case.objects.create(reporter=user, description="t")
        emit_mock.assert_called_once_with("case_created", case)

    def test_case_update_does_not_emit(self):
        user = make_user()
        case = Case.objects.create(reporter=user, description="t")
        with mock.patch("connectors.signals.emit") as emit_mock:
            case.status = "Done"
            case.save()
        emit_mock.assert_not_called()
