"""Tests for federation SDK methods (Phase 39)."""

import pytest
import httpx

from vellaveto.client import (
    AsyncVellavetoClient,
    VellavetoClient,
    VellavetoError,
)


class TestFederationStatusSync:
    """Tests for VellavetoClient.federation_status()."""

    def test_federation_status_success(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/status",
            json={
                "enabled": True,
                "trust_anchor_count": 1,
                "anchors": [
                    {
                        "org_id": "partner-org",
                        "display_name": "Partner",
                        "trust_level": "limited",
                        "successful_validations": 42,
                        "failed_validations": 3,
                    }
                ],
            },
        )
        client = VellavetoClient()
        result = client.federation_status()
        assert result["enabled"] is True
        assert result["trust_anchor_count"] == 1
        assert len(result["anchors"]) == 1
        assert result["anchors"][0]["org_id"] == "partner-org"
        client.close()

    def test_federation_status_disabled(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/status",
            json={"enabled": False, "trust_anchor_count": 0, "anchors": []},
        )
        client = VellavetoClient()
        result = client.federation_status()
        assert result["enabled"] is False
        assert result["trust_anchor_count"] == 0
        client.close()

    def test_federation_status_http_error(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/status",
            status_code=404,
        )
        client = VellavetoClient()
        with pytest.raises(VellavetoError):
            client.federation_status()
        client.close()


class TestFederationTrustAnchorsSync:
    """Tests for VellavetoClient.federation_trust_anchors()."""

    def test_federation_trust_anchors_list_all(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/trust-anchors",
            json={
                "anchors": [
                    {"org_id": "org-1", "display_name": "Org 1", "trust_level": "full"},
                    {"org_id": "org-2", "display_name": "Org 2", "trust_level": "limited"},
                ],
                "total": 2,
            },
        )
        client = VellavetoClient()
        result = client.federation_trust_anchors()
        assert result["total"] == 2
        assert len(result["anchors"]) == 2
        client.close()

    def test_federation_trust_anchors_filter_by_org_id(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/federation/trust-anchors",
                params={"org_id": "org-1"},
            ),
            json={"anchors": [{"org_id": "org-1"}], "total": 1},
        )
        client = VellavetoClient()
        result = client.federation_trust_anchors(org_id="org-1")
        assert result["total"] == 1
        client.close()

    def test_federation_trust_anchors_org_id_too_long(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="max length"):
            client.federation_trust_anchors(org_id="x" * 129)
        client.close()

    def test_federation_trust_anchors_org_id_control_chars(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="control"):
            client.federation_trust_anchors(org_id="org\x00id")
        client.close()

    def test_federation_trust_anchors_org_id_newline(self):
        client = VellavetoClient()
        with pytest.raises(VellavetoError, match="control"):
            client.federation_trust_anchors(org_id="org\nid")
        client.close()

    def test_federation_trust_anchors_empty(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/trust-anchors",
            json={"anchors": [], "total": 0},
        )
        client = VellavetoClient()
        result = client.federation_trust_anchors()
        assert result["total"] == 0
        assert result["anchors"] == []
        client.close()


class TestFederationStatusAsync:
    """Tests for AsyncVellavetoClient.federation_status()."""

    @pytest.mark.asyncio
    async def test_async_federation_status(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/status",
            json={
                "enabled": True,
                "trust_anchor_count": 2,
                "anchors": [],
            },
        )
        async with AsyncVellavetoClient() as client:
            result = await client.federation_status()
            assert result["enabled"] is True
            assert result["trust_anchor_count"] == 2

    @pytest.mark.asyncio
    async def test_async_federation_status_disabled(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/status",
            json={"enabled": False, "trust_anchor_count": 0, "anchors": []},
        )
        async with AsyncVellavetoClient() as client:
            result = await client.federation_status()
            assert result["enabled"] is False


class TestFederationTrustAnchorsAsync:
    """Tests for AsyncVellavetoClient.federation_trust_anchors()."""

    @pytest.mark.asyncio
    async def test_async_federation_trust_anchors_list_all(self, httpx_mock):
        httpx_mock.add_response(
            url="http://localhost:3000/api/federation/trust-anchors",
            json={"anchors": [{"org_id": "org-1"}], "total": 1},
        )
        async with AsyncVellavetoClient() as client:
            result = await client.federation_trust_anchors()
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_async_federation_trust_anchors_filter(self, httpx_mock):
        httpx_mock.add_response(
            url=httpx.URL(
                "http://localhost:3000/api/federation/trust-anchors",
                params={"org_id": "partner"},
            ),
            json={"anchors": [{"org_id": "partner"}], "total": 1},
        )
        async with AsyncVellavetoClient() as client:
            result = await client.federation_trust_anchors(org_id="partner")
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_async_federation_trust_anchors_org_id_too_long(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="max length"):
                await client.federation_trust_anchors(org_id="x" * 129)

    @pytest.mark.asyncio
    async def test_async_federation_trust_anchors_org_id_control_chars(self):
        async with AsyncVellavetoClient() as client:
            with pytest.raises(VellavetoError, match="control"):
                await client.federation_trust_anchors(org_id="org\x01id")
