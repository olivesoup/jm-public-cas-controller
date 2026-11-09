"""Synthetic source tests, mocked GitHub REST; NOT actual remote CAS proof."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "ledger" / "github_nonce_cas.py"
spec = importlib.util.spec_from_file_location("github_nonce_cas", p)
cas = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cas
spec.loader.exec_module(cas)

NONCE = "b" * 32
CLAIM = "c" * 64
MASTER = "d" * 40
TAG_SHA = "e" * 40
PREFIX = "/repos/olivesoup/jm-gate-witness"


class FakeGitHub:
    def __init__(self):
        self.refs = {}
        self.tag_objects = {}
        self.rules = [{
            "id": 9001, "name": cas.RULESET_NAME, "target": "tag",
            "enforcement": "active",
        }]
        self.detail = {
            "id": 9001, "name": cas.RULESET_NAME, "target": "tag",
            "enforcement": "active", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/tags/jm-cas/v1/*"], "exclude": []}},
            "rules": [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}, {"type": "deletion"}],
        }
        self.master = {"commit": {"sha": MASTER}, "protected": True}
        self.tries = 0

    def call(self, method, path, body):
        if (method, path) == ("GET", PREFIX + "/rulesets"):
            return self.rules
        if (method, path) == ("GET", PREFIX + "/rulesets/9001"):
            return self.detail
        if (method, path) == ("GET", PREFIX + "/branches/master"):
            return self.master
        if (method, path) == ("POST", PREFIX + "/git/tags"):
            assert body["object"] == MASTER and body["type"] == "commit"
            assert json.loads(body["message"])["real_gate"] is False
            self.tag_objects[TAG_SHA] = {
                "sha": TAG_SHA, "tag": body["tag"], "message": body["message"],
                "object": {"sha": body["object"], "type": body["type"]},
            }
            return {"sha": TAG_SHA}
        if (method, path) == ("GET", PREFIX + "/git/tags/" + TAG_SHA):
            return self.tag_objects[TAG_SHA]
        if (method, path) == ("POST", PREFIX + "/git/refs"):
            self.tries += 1
            ref = body["ref"]
            if ref in self.refs:
                raise RuntimeError("GITHUB_REJECTED_422_ALREADY_EXISTS")
            self.refs[ref] = body["sha"]
            return {"ref": ref, "object": {"sha": body["sha"], "type": "tag"}}
        if method == "GET" and path.startswith(PREFIX + "/git/ref/tags/"):
            ref = "refs/" + path.split("/git/ref/", 1)[1]
            return {"ref": ref, "object": {"sha": self.refs[ref], "type": "tag"}}
        raise AssertionError((method, path))


class CasUnit(unittest.TestCase):
    def test_synthetic_once_not_global_gate(self):
        db = FakeGitHub()
        r = cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)
        self.assertTrue(r["exclusive_ref_create_observed"])
        self.assertFalse(r["global_nonrollback_proven"])
        self.assertFalse(r["product_gate"])

    def test_same_nonce_replay_is_denied_even_if_digest_changes(self):
        db = FakeGitHub()
        cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)
        with self.assertRaisesRegex(cas.CasDenied, "ALREADY_CONSUMED"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256="f" * 64, master_sha=MASTER)
        self.assertEqual(db.tries, 2)

    def test_different_nonces_distinct(self):
        db = FakeGitHub()
        cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)
        cas.commit_synthetic_nonce(db.call, nonce="a" * 32, claim_sha256=CLAIM, master_sha=MASTER)
        self.assertEqual(len(db.refs), 2)

    def test_nonce_input_must_be_exact_hex(self):
        for value in ("", "a", "A" * 32, "a/" * 16, "../" + "a" * 29):
            with self.subTest(value=value):
                with self.assertRaisesRegex(cas.CasDenied, "NONCE"):
                    cas.validate(value, CLAIM, MASTER)

    def test_claim_digest_must_be_hex_sha256(self):
        with self.assertRaisesRegex(cas.CasDenied, "DIGEST"):
            cas.validate(NONCE, "g" * 64, MASTER)

    def test_wrong_master_head_denied(self):
        db = FakeGitHub()
        db.master["commit"]["sha"] = "0" * 40
        with self.assertRaisesRegex(cas.CasDenied, "PROTECTED_MASTER_MOVED"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_unprotected_master_denied(self):
        db = FakeGitHub()
        db.master["protected"] = False
        with self.assertRaisesRegex(cas.CasDenied, "PROTECTED_MASTER_MOVED"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_rule_disabled_denied(self):
        db = FakeGitHub()
        db.detail["enforcement"] = "disabled"
        with self.assertRaisesRegex(cas.CasDenied, "INACTIVE"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_rule_bypass_denied(self):
        db = FakeGitHub()
        db.detail["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
        with self.assertRaisesRegex(cas.CasDenied, "BYPASS"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_noncanonical_update_rule_params_denied(self):
        db = FakeGitHub()
        db.detail["rules"][0]["parameters"] = {"update_allows_fetch_and_merge": True}
        with self.assertRaisesRegex(cas.CasDenied, "UPDATE_RULE_PARAMETER_UNSAFE"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_tag_get_omits_update_params_and_policy_still_matches(self):
        db = FakeGitHub()
        del db.detail["rules"][0]["parameters"]
        receipt = cas.commit_synthetic_nonce(db.call, nonce=NONCE,
                                             claim_sha256=CLAIM, master_sha=MASTER)
        self.assertTrue(receipt["exclusive_ref_create_observed"])
        self.assertFalse(receipt["global_nonrollback_proven"])

    def test_tag_get_null_update_params_policy_still_matches(self):
        db = FakeGitHub()
        db.detail["rules"][0]["parameters"] = None
        receipt = cas.commit_synthetic_nonce(db.call, nonce=NONCE,
                                             claim_sha256=CLAIM, master_sha=MASTER)
        self.assertFalse(receipt["product_gate"])

    def test_unexpected_update_params_denied(self):
        db = FakeGitHub()
        db.detail["rules"][0]["parameters"] = {"update_allows_fetch_and_merge": False,
                                                 "extra": True}
        with self.assertRaisesRegex(cas.CasDenied, "UPDATE_RULE_PARAMETER_UNSAFE"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_rule_update_protection_missing_denied(self):
        db = FakeGitHub()
        db.detail["rules"] = [{"type": "deletion"}]
        with self.assertRaisesRegex(cas.CasDenied, "PROTECTION"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_wrong_target_pattern_denied(self):
        db = FakeGitHub()
        db.detail["conditions"]["ref_name"]["include"] = ["*"]
        with self.assertRaisesRegex(cas.CasDenied, "TARGET_CHANGED"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_duplicate_rulesets_denied(self):
        db = FakeGitHub()
        db.rules.append(dict(db.rules[0], id=123))
        with self.assertRaisesRegex(cas.CasDenied, "DISCOVERY_NOT_UNIQUE"):
            cas.commit_synthetic_nonce(db.call, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_ref_readback_drift_denied(self):
        db = FakeGitHub()
        def altered(method, path, body):
            val = db.call(method, path, body)
            if method == "GET" and "/git/ref/tags/" in path:
                return dict(val, object={"sha": "0" * 40})
            return val
        with self.assertRaisesRegex(cas.CasDenied, "READBACK_MISMATCH"):
            cas.commit_synthetic_nonce(altered, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_annotated_tag_message_readback_drift_denied(self):
        db = FakeGitHub()
        def forged(method, path, body):
            value = db.call(method, path, body)
            if method == "GET" and "/git/tags/" in path:
                return dict(value, message="{}")
            return value
        with self.assertRaisesRegex(cas.CasDenied, "TAG_OBJECT_READBACK_MISMATCH"):
            cas.commit_synthetic_nonce(forged, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)
        self.assertEqual(db.tries, 0, "Tag mismatch must block before ref creation")

    def test_annotated_target_drift_denied(self):
        db = FakeGitHub()
        def forged(method, path, body):
            value = db.call(method, path, body)
            if method == "GET" and "/git/tags/" in path:
                return dict(value, object={"sha": "0" * 40, "type": "commit"})
            return value
        with self.assertRaisesRegex(cas.CasDenied, "TAG_OBJECT_READBACK_MISMATCH"):
            cas.commit_synthetic_nonce(forged, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_ref_not_annotated_tag_type_denied(self):
        db = FakeGitHub()
        def forged(method, path, body):
            value = db.call(method, path, body)
            if method == "GET" and "/git/ref/tags/" in path:
                return dict(value, object={"sha": TAG_SHA, "type": "commit"})
            return value
        with self.assertRaisesRegex(cas.CasDenied, "LIVE_REF_READBACK_MISMATCH"):
            cas.commit_synthetic_nonce(forged, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_policy_revoked_after_ref_creation_denied(self):
        db = FakeGitHub()
        count = [0]
        def mutate(method, path, body):
            if method == "GET" and path == PREFIX + "/rulesets/9001":
                count[0] += 1
                if count[0] > 1:
                    db.detail["enforcement"] = "disabled"
            return db.call(method, path, body)
        with self.assertRaisesRegex(cas.CasDenied, "CAS_RULESET_INACTIVE"):
            cas.commit_synthetic_nonce(mutate, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)
        self.assertEqual(db.tries, 1, "A ref may exist despite fail-closed receipt")

    def test_master_moved_after_ref_creation_denied(self):
        db = FakeGitHub()
        count = [0]
        def mutate(method, path, body):
            if method == "GET" and path == PREFIX + "/branches/master":
                count[0] += 1
                if count[0] > 1:
                    db.master["commit"]["sha"] = "0" * 40
            return db.call(method, path, body)
        with self.assertRaisesRegex(cas.CasDenied, "MASTER_CHANGED_AFTER_WRITE"):
            cas.commit_synthetic_nonce(mutate, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)
        self.assertEqual(db.tries, 1)

    def test_rule_disappeared_after_ref_creation_denied(self):
        db = FakeGitHub()
        count = [0]
        def mutate(method, path, body):
            if method == "GET" and path == PREFIX + "/rulesets":
                count[0] += 1
                if count[0] > 1:
                    db.rules = []
            return db.call(method, path, body)
        with self.assertRaisesRegex(cas.CasDenied, "RULESET_CHANGED_AFTER_WRITE"):
            cas.commit_synthetic_nonce(mutate, nonce=NONCE, claim_sha256=CLAIM, master_sha=MASTER)

    def test_synthetic_receipt_never_claims_global_atomic_race(self):
        db = FakeGitHub()
        receipt = cas.commit_synthetic_nonce(db.call, nonce=NONCE,
                                              claim_sha256=CLAIM, master_sha=MASTER)
        self.assertTrue(receipt["exclusive_ref_create_observed"])
        self.assertNotIn("atomic_ref_create", receipt)
        self.assertFalse(receipt["global_nonrollback_proven"])

    def test_metadata_is_public_hashonly(self):
        meta = json.loads(cas.tag_message(NONCE, CLAIM, MASTER))
        self.assertEqual(set(meta), {
            "schema", "issuer", "claim_kind", "nonce", "public_claim_sha256",
            "protected_master_sha", "real_gate",
        })
        self.assertNotIn("path", meta)
        self.assertNotIn("token", meta)


if __name__ == "__main__":
    unittest.main()
