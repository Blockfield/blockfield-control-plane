import json
import os
import tempfile
import unittest
import urllib.request

import api


def body(res):
    return json.loads(res.read().decode())


class GateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.path.join(tempfile.mkdtemp(), "cp.sqlite")
        os.environ["CP_BOOTSTRAP_ADMIN_SECRET"] = "test-secret"
        cls.store = api.Store(path)
        cls.seeds = cls.store.bootstrap("test-secret")
        # second bootstrap is a no-op (rotation overlap is U2)
        assert cls.store.bootstrap("other") == {}
        cls.server = api.ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        cls.server.store = cls.store
        cls.port = cls.server.server_address[1]
        import threading

        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    def req(self, method, path, token=None, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            r.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(r) as res:
                return res.status, body(res)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_openapi_public(self):
        code, doc = self.req("GET", "/v1/openapi.json")
        self.assertEqual(code, 200)
        self.assertIn("/v1/gate", doc["paths"])

    def test_gate_needs_scoped_token(self):
        self.assertEqual(self.req("GET", "/v1/gate")[0], 401)
        self.assertEqual(
            self.req("GET", "/v1/gate", token="bogus")[0], 401
        )
        # proxy seed has gate:read but not gate:write
        code, _ = self.req(
            "POST",
            "/v1/gate",
            token=self.seeds["proxy"],
            payload={"mode": "open", "actor": {"id": "a", "role": "admin"}},
        )
        self.assertEqual(code, 401)

    def test_gate_roundtrip(self):
        code, g = self.req("GET", "/v1/gate", token=self.seeds["proxy"])
        self.assertEqual(code, 200)
        self.assertEqual(g["schema"], 1)
        self.assertEqual(g["mode"], "open")
        rev = g["revision"]
        code, out = self.req(
            "POST",
            "/v1/gate",
            token=self.seeds["site"],
            payload={
                "expectedRevision": rev,
                "idempotencyKey": "k1",
                "mode": "maintenance",
                "message": "Техработы",
                "actor": {"id": "owner-1", "role": "owner"},
            },
        )
        self.assertEqual(code, 202)
        self.assertEqual(out["revision"], rev + 1)
        _, g = self.req("GET", "/v1/gate", token=self.seeds["proxy"])
        self.assertEqual((g["mode"], g["message"], g["revision"]), ("maintenance", "Техработы", rev + 1))
        self.assertGreaterEqual(g["observedAt"], g["since"])

    def test_revision_conflict_and_idempotency(self):
        _, g = self.req("GET", "/v1/gate", token=self.seeds["proxy"])
        site = self.seeds["site"]
        actor = {"id": "admin-2", "role": "admin"}
        bad = {"expectedRevision": 0, "idempotencyKey": "k2", "mode": "open", "actor": actor}
        code, doc = self.req("POST", "/v1/gate", token=site, payload=bad)
        self.assertEqual(code, 409)
        self.assertEqual(doc["revision"], g["revision"])
        good = dict(bad, expectedRevision=g["revision"])
        code, first = self.req("POST", "/v1/gate", token=site, payload=good)
        self.assertEqual(code, 202)
        code, again = self.req("POST", "/v1/gate", token=site, payload=good)
        self.assertEqual((code, again), (202, first))  # same key+body -> same operation
        changed = dict(good, mode="maintenance")
        self.assertEqual(
            self.req("POST", "/v1/gate", token=site, payload=changed)[0], 409
        )  # same key, changed body
        self.assertEqual(
            self.req(
                "POST", "/v1/gate", token=site,
                payload=dict(good, idempotencyKey="k3", actor={"id": "x", "role": "mod"}),
            )[0],
            400,
        )  # only owner/admin may toggle

    def test_every_write_is_audited(self):
        _, g = self.req("GET", "/v1/gate", token=self.seeds["proxy"])
        code, out = self.req(
            "POST", "/v1/gate", token=self.seeds["site"],
            payload={
                "expectedRevision": g["revision"], "idempotencyKey": "audit-k",
                "mode": g["mode"], "actor": {"id": "owner-9", "role": "owner"},
            },
        )
        self.assertEqual(code, 202)
        row = self.store.db.execute(
            "SELECT actor,action,detail FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual((row[0], row[1]), ("owner-9:owner", "gate:set"))
        self.assertIn(str(out["revision"]), row[2])


if __name__ == "__main__":
    unittest.main()
