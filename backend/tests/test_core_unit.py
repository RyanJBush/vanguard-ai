from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.dependencies import get_current_user, require_roles
from app.models import Role, User
from app.observability import RequestContextFilter, attach_request_context_filter
from app.services.ai_assistant import build_alert_summary, build_triage_recommendation
from app.services.pagination import paginate_query


class _FakeQuery:
    def __init__(self, values):
        self.values = values
        self._offset = 0
        self._limit = len(values)

    def count(self):
        return len(self.values)

    def offset(self, value):
        self._offset = value
        return self

    def limit(self, value):
        self._limit = value
        return self

    def all(self):
        return self.values[self._offset : self._offset + self._limit]


def test_paginate_query_clamps_bounds_and_returns_metadata():
    query = _FakeQuery(list(range(10)))

    items, total, page, page_size = paginate_query(query, page=0, page_size=1000)

    assert total == 10
    assert page == 1
    assert page_size == 200
    assert items == list(range(10))


def test_get_current_user_rejects_missing_subject():
    class FakeDB:
        pass

    with pytest.raises(HTTPException) as exc:
        get_current_user(token="", db=FakeDB())
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


def test_require_roles_enforces_permissions():
    admin = User(id=1, username="admin", full_name="Admin", password_hash="x", role=Role.admin, organization_id=1)
    viewer = User(id=2, username="viewer", full_name="Viewer", password_hash="x", role=Role.viewer, organization_id=1)

    guard = require_roles(Role.admin)
    assert guard(user=admin) == admin

    with pytest.raises(HTTPException) as exc:
        guard(user=viewer)
    assert exc.value.status_code == 403
    assert exc.value.detail == "Insufficient permissions"


def test_attach_request_context_filter_is_idempotent():
    root = logging.getLogger()
    before = len([flt for flt in root.filters if isinstance(flt, RequestContextFilter)])
    attach_request_context_filter()
    mid = len([flt for flt in root.filters if isinstance(flt, RequestContextFilter)])
    attach_request_context_filter()
    after = len([flt for flt in root.filters if isinstance(flt, RequestContextFilter)])
    assert mid >= before
    assert after == mid


def test_ai_assistant_summary_and_priority_mapping():
    alert = SimpleNamespace(
        title="Brute force detected",
        severity="high",
        confidence_score=0.9123,
        dedup_count=3,
        mitre_techniques=["T1110"],
        correlation_id="brute_force_login_rule:203.0.113.2",
        recommended_next_steps="disable account",
    )

    summary = build_alert_summary(alert)
    recommendation, priority = build_triage_recommendation(alert)

    assert "Brute force detected" in summary
    assert "T1110" in summary
    assert priority == "P1"
    assert "disable account" in recommendation
