"""Cloud identity per sandbox: the create option, the sandbox's identity
view and the admin role-tag calls (plans/sandbox-cloud-identity.md)."""

import unittest

from microvm import MicroVM
from microvm.client import _from_api_sandbox, _to_api_create_options


class IdentityRecordingMicroVM(MicroVM):
    def __init__(self) -> None:
        super().__init__(api_url="https://sandbox.example.com", pat_token="pat-token")
        self.calls = []
        self.idempotent = []

    def _do_json(self, method, path, payload, *, idempotent=True, headers=None):  # type: ignore[override]
        self.calls.append((method, path, payload))
        self.idempotent.append(idempotent)
        if path.startswith("/v1/identity/roles?") or path == "/v1/identity/roles":
            return {
                "roles": [{"tag": "deploy", "min_role": "runner", "team": "payments", "created_at": "c", "updated_at": "u"}],
                "next_cursor": "deploy",
            }
        if method == "PUT" and path.startswith("/v1/identity/roles/"):
            return {"tag": "deploy", "min_role": payload["min_role"], "team": "payments", "created_at": "c", "updated_at": "u"}
        return {}


class IdentityTests(unittest.TestCase):
    def test_create_option_maps_to_the_wire(self):
        body = _to_api_create_options(
            {
                "image": "alpine",
                "identity": {
                    "roleTag": "deploy",
                    "audience": "api://AzureADTokenExchange",
                    "awsRoleArn": "arn:aws:iam::123456789012:role/deploy",
                    "azureClientId": "c",
                    "azureTenantId": "t",
                },
            }
        )
        self.assertEqual(
            body["identity"],
            {
                "role_tag": "deploy",
                "audience": "api://AzureADTokenExchange",
                "aws_role_arn": "arn:aws:iam::123456789012:role/deploy",
                "azure_client_id": "c",
                "azure_tenant_id": "t",
            },
        )
        # Unset fields stay off the wire; no identity sends nothing.
        self.assertEqual(_to_api_create_options({"image": "a", "identity": {"roleTag": "x"}})["identity"], {"role_tag": "x"})
        self.assertNotIn("identity", _to_api_create_options({"image": "a"}))

    def test_sandbox_identity_view(self):
        data = _from_api_sandbox(
            {
                "id": "sb",
                "identity": {
                    "role_tag": "deploy",
                    "audience": "sts.amazonaws.com",
                    "subject": "team:payments:role:deploy",
                    "aws_role_arn": "arn:aws:iam::123456789012:role/deploy",
                    "token_file": "/run/aerolvm/identity/token",
                    "token_expires_at": "2026-11-06T12:00:00Z",
                },
            }
        )
        self.assertEqual(
            data["identity"],
            {
                "roleTag": "deploy",
                "audience": "sts.amazonaws.com",
                "subject": "team:payments:role:deploy",
                "awsRoleArn": "arn:aws:iam::123456789012:role/deploy",
                "tokenFile": "/run/aerolvm/identity/token",
                "tokenExpiresAt": "2026-11-06T12:00:00Z",
            },
        )
        self.assertNotIn("identity", _from_api_sandbox({"id": "sb"}))

    def test_role_calls(self):
        client = IdentityRecordingMicroVM()
        role = client.put_identity_role("deploy", {"minRole": "runner", "team": "payments"})
        self.assertEqual(client.calls[0], ("PUT", "/v1/identity/roles/deploy?team=payments", {"min_role": "runner"}))
        self.assertEqual(role, {"tag": "deploy", "minRole": "runner", "team": "payments", "createdAt": "c", "updatedAt": "u"})
        page = client.list_identity_roles({"team": "payments", "cursor": "a", "limit": 10})
        self.assertEqual(client.calls[1][1], "/v1/identity/roles?team=payments&cursor=a&limit=10")
        self.assertEqual(page["roles"][0]["minRole"], "runner")
        self.assertEqual(page["nextCursor"], "deploy")
        client.list_identity_roles()
        self.assertEqual(client.calls[2][1], "/v1/identity/roles")
        client.delete_identity_role("deploy", {"team": "payments"})
        self.assertEqual(client.calls[3][:2], ("DELETE", "/v1/identity/roles/deploy?team=payments"))
        # The operator namespace: no team parameter at all.
        client.put_identity_role("ops", {"minRole": "admin"})
        self.assertEqual(client.calls[4][1], "/v1/identity/roles/ops")
        client.delete_identity_role("ops")
        self.assertEqual(client.calls[5][1], "/v1/identity/roles/ops")
        # Every role call is idempotent, so all retry on the safe tier.
        self.assertTrue(all(client.idempotent))


if __name__ == "__main__":
    unittest.main()
