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

    def test_expected_revision_rejects_bool_and_float(self):
        # P1-5 (control-plane#8): Python True == 1 / False == 0, so a bool or
        # float revision slips past `expected != rev` and double-applies.
        store = api.Store(":memory:")
        store.bootstrap("prodfix-secret")
        for bad_revision in (False, True, 0.0, 1.0, "0"):
            with self.assertRaises(api.Bad, msg=f"expectedRevision={bad_revision!r}"):
                store.set_gate(
                    "maintenance",
                    "",
                    "owner-8",
                    "owner",
                    bad_revision,
                    f"k-{bad_revision!r}",
                )
        self.assertEqual(store.gate()["revision"], 0)
        self.assertEqual(
            store.db.execute("SELECT COUNT(*) FROM gate_log").fetchone()[0], 0
        )
        out = store.set_gate("maintenance", "", "owner-8", "owner", 0, "k-int")
        self.assertEqual(out["revision"], 1)

    def test_expected_revision_float_rejected_over_http(self):
        # Order-independent HTTP cover: float(rev) == rev is always True.
        _, g = self.req("GET", "/v1/gate", token=self.seeds["proxy"])
        code, _ = self.req(
            "POST",
            "/v1/gate",
            token=self.seeds["site"],
            payload={
                "expectedRevision": float(g["revision"]),
                "idempotencyKey": "float-k",
                "mode": g["mode"],
                "actor": {"id": "owner-8", "role": "owner"},
            },
        )
        self.assertEqual(code, 400)

    def test_expected_revision_bool_rejected_over_http_at_rev_zero(self):
        # control-plane#8 exact repro: POST {expectedRevision:false} at rev 0
        # must be 400 with no revision bump (True == 1 / False == 0 in Python).
        import threading

        store = api.Store(":memory:")
        seeds = store.bootstrap("bool-secret")
        server = api.ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        server.store = store
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def post(payload):
            import urllib.error

            r = urllib.request.Request(
                base + "/v1/gate",
                data=json.dumps(payload).encode(),
                method="POST",
                headers={"Authorization": "Bearer " + seeds["site"]},
            )
            try:
                with urllib.request.urlopen(r) as res:
                    return res.status
            except urllib.error.HTTPError as e:
                return e.code

        for bad in (False, True):
            code = post(
                {
                    "expectedRevision": bad,
                    "idempotencyKey": f"bool-{bad}",
                    "mode": "maintenance",
                    "actor": {"id": "owner-8", "role": "owner"},
                }
            )
            self.assertEqual(code, 400)
        self.assertEqual(store.gate()["revision"], 0)
        self.assertEqual(
            store.db.execute("SELECT COUNT(*) FROM gate_log").fetchone()[0], 0
        )
        server.shutdown()

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

    def test_audit_records_authenticated_client(self):
        # E3 (#13): the actor is a forwarded claim, so the audit must also
        # record which authenticated token submitted the write.
        _, g = self.req("GET", "/v1/gate", token=self.seeds["proxy"])
        code, _ = self.req(
            "POST",
            "/v1/gate",
            token=self.seeds["site"],
            payload={
                "expectedRevision": g["revision"],
                "idempotencyKey": "client-k",
                "mode": g["mode"],
                "actor": {"id": "invented-owner", "role": "owner"},
            },
        )
        self.assertEqual(code, 202)
        row = self.store.db.execute(
            "SELECT actor,detail FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], "invented-owner:owner")
        self.assertEqual(json.loads(row[1])["client"], "site")


    def test_health_public_ok(self):
        # CP-H5: unauthenticated liveness for deploy gates/Dokploy.
        code, doc = self.req("GET", "/health")
        self.assertEqual(code, 200)
        self.assertEqual(doc, {"status": "ok", "schema": 1})

    def test_health_reports_store_outage(self):
        import threading

        broken = api.Store(os.path.join(tempfile.mkdtemp(), "cp-broken.sqlite"))
        broken.db.close()
        server = api.ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        server.store = broken
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            self.assertEqual(cm.exception.code, 503)
            self.assertEqual(
                json.loads(cm.exception.read().decode()),
                {"status": "unavailable", "schema": 1},
            )
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
