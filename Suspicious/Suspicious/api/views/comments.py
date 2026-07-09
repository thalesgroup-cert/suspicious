from __future__ import annotations

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.submissions import user_has_submission_elevated_access
from api.serializers.comments import CaseCommentSerializer
from case_handler.models import Case


class CaseCommentListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get_case(self, request, case_id: int) -> Case:
        queryset = Case.objects.all()
        if not user_has_submission_elevated_access(request.user):
            queryset = queryset.filter(reporter=request.user)
        return get_object_or_404(queryset, pk=case_id)

    def get(self, request, case_id: int):
        case = self.get_case(request, case_id)
        comments = case.comments.all()
        if not user_has_submission_elevated_access(request.user):
            comments = comments.filter(is_internal=False)
        serializer = CaseCommentSerializer(comments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, case_id: int):
        case = self.get_case(request, case_id)
        serializer = CaseCommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        is_internal = user_has_submission_elevated_access(request.user)
        comment = serializer.save(case=case, author=request.user, is_internal=is_internal)
        return Response(CaseCommentSerializer(comment).data, status=status.HTTP_201_CREATED)
