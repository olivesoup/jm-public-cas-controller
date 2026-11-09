"""GitHub public ref-backed NONCE CAS primitive, not product/Host authority.

Only for already-verified PUBLIC synthetic claims under protected witness master.
No private payloads, no arbitrary repo, no GitHub token in stdout.
"""
from __future__ import annotations

import json
import re
from typing import Callable

REPO = "olivesoup/jm-gate-witness"
RULESET_NAME = "JM-Public-Nonce-CAS-Append-Only"
PREFIX = "jm-cas/v1/"
DIGEST = re.compile(r"^[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
NONCE = re.compile(r"^[a-f0-9]{32}$")


class CasDenied(RuntimeError):
    pass


def validate(nonce: object, claim_sha256: object, master_sha: object):
    if type(nonce) is not str or not NONCE.fullmatch(nonce):
        raise CasDenied("CAS_NONCE_INVALID")
    if type(claim_sha256) is not str or not DIGEST.fullmatch(claim_sha256):
        raise CasDenied("CAS_PUBLIC_CLAIM_DIGEST_INVALID")
    if type(master_sha) is not str or not SHA.fullmatch(master_sha):
        raise CasDenied("CAS_MASTER_SHA_INVALID")


def tag_name(nonce: str):
    if type(nonce) is not str or not NONCE.fullmatch(nonce):
        raise CasDenied("CAS_NONCE_INVALID")
    return PREFIX + nonce


def tag_message(nonce: str, claim_sha256: str, master_sha: str) -> str:
    validate(nonce, claim_sha256, master_sha)
    fields = {
        "schema": "JM_PUBLIC_NONCE_CAS_TAG_V1",
        "issuer": REPO,
        "claim_kind": "EVIDENCE_ONLY_NOT_GATE",
        "nonce": nonce,
        "public_claim_sha256": claim_sha256,
        "protected_master_sha": master_sha,
        "real_gate": False,
    }
    return json.dumps(fields, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False) + "\n"


def _ruleset_ready(rulesets: object) -> None:
    if type(rulesets) is not list:
        raise CasDenied("CAS_RULESETS_UNAVAILABLE")
    matches = [x for x in rulesets if type(x) is dict
               and x.get("name") == RULESET_NAME]
    if len(matches) != 1:
        raise CasDenied("CAS_RULESET_NOT_UNIQUE")
    rule = matches[0]
    if (rule.get("target") != "tag" or rule.get("enforcement") != "active"):
        raise CasDenied("CAS_RULESET_INACTIVE")
    if rule.get("bypass_actors") != []:
        raise CasDenied("CAS_RULESET_BYPASS")
    cond = rule.get("conditions", {}).get("ref_name", {})
    if cond.get("include") != ["refs/tags/" + PREFIX + "*"] or cond.get("exclude") != []:
        raise CasDenied("CAS_REF_TARGET_CHANGED")
    r_types = {r.get("type") for r in rule.get("rules", []) if type(r) is dict}
    if r_types != {"update", "deletion"} or len(rule.get("rules", [])) != 2:
        raise CasDenied("CAS_UPDATE_DELETE_PROTECTION_MISSING")
    updates = [r for r in rule["rules"] if r.get("type") == "update"]
    if len(updates) != 1:
        raise CasDenied("CAS_UPDATE_RULE_MISSING_OR_DUPLICATE")
    # GitHub GET omits the branch-only update parameter for tag rules.
    # The exact TAG update+deletion protections and zero-bypass still apply.
    # If returned, permit only an explicit false value, no other keys.
    if "parameters" in updates[0] and updates[0]["parameters"] is not None:
        params = updates[0]["parameters"]
        if (type(params) is not dict or
                params != {"update_allows_fetch_and_merge": False}):
            raise CasDenied("CAS_UPDATE_RULE_PARAMETER_UNSAFE")


def commit_synthetic_nonce(transport: Callable, *, nonce: str,
                           claim_sha256: str, master_sha: str) -> dict:
    """transport(method,path,json) returns decoded REST response or raises.

    Request transport is trusted runner code and must NOT use PR-controlled
    code/tokens. Creates a Git object then exclusive tag ref exactly once.
    """
    validate(nonce, claim_sha256, master_sha)
    prefix = "/repos/" + REPO
    rulesets = transport("GET", prefix + "/rulesets", None)
    if type(rulesets) is not list:
        raise CasDenied("CAS_RULESETS_UNAVAILABLE")
    matches = [r for r in rulesets if type(r) is dict
               and r.get("name") == RULESET_NAME and r.get("target") == "tag"
               and type(r.get("id")) is int]
    if len(matches) != 1:
        raise CasDenied("CAS_RULESET_DISCOVERY_NOT_UNIQUE")
    detail = transport("GET", prefix + "/rulesets/" + str(matches[0]["id"]), None)
    _ruleset_ready([detail])
    active_master = transport("GET", prefix + "/branches/master", None)
    if (type(active_master) is not dict or
        active_master.get("protected") is not True or
        active_master.get("commit", {}).get("sha") != master_sha):
        raise CasDenied("CAS_PROTECTED_MASTER_MOVED_OR_UNTRUSTED")
    name = tag_name(nonce)
    created = transport("POST", prefix + "/git/tags", {
        "tag": name,
        "message": tag_message(nonce, claim_sha256, master_sha),
        "object": master_sha,
        "type": "commit",
    })
    if type(created) is not dict or type(created.get("sha")) is not str or not SHA.fullmatch(created["sha"]):
        raise CasDenied("CAS_ANNOTATED_TAG_OBJECT_NOT_CONFIRMED")
    tag_sha = created["sha"]
    expected_message = tag_message(nonce, claim_sha256, master_sha)

    def verify_tag_object():
        stored = transport("GET", prefix + "/git/tags/" + tag_sha, None)
        if (type(stored) is not dict or
            stored.get("sha") != tag_sha or
            stored.get("tag") != name or
            stored.get("message") != expected_message or
            type(stored.get("object")) is not dict or
            stored["object"].get("type") != "commit" or
            stored["object"].get("sha") != master_sha):
            raise CasDenied("CAS_ANNOTATED_TAG_OBJECT_READBACK_MISMATCH")

    verify_tag_object()  # Tag SHA alone never binds the exact nonce and claim.
    try:
        response = transport("POST", prefix + "/git/refs", {
            "ref": "refs/tags/" + name,
            "sha": tag_sha,
        })
    except Exception as exc:
        raise CasDenied("CAS_NONCE_ALREADY_CONSUMED_OR_REGISTRY_UNAVAILABLE") from exc
    if (type(response) is not dict or
        response.get("ref") != "refs/tags/" + name or
        response.get("object", {}).get("sha") != tag_sha):
        raise CasDenied("CAS_REFERENCE_CREATE_UNVERIFIED")
    observed = transport("GET", prefix + "/git/ref/tags/" + name, None)
    if (type(observed) is not dict or
        observed.get("ref") != "refs/tags/" + name or
        type(observed.get("object")) is not dict or
        observed["object"].get("sha") != tag_sha or
        observed["object"].get("type") != "tag"):
        raise CasDenied("CAS_LIVE_REF_READBACK_MISMATCH")

    verify_tag_object()  # Detect post-write object drift before any receipt.
    latest_rulesets = transport("GET", prefix + "/rulesets", None)
    if (type(latest_rulesets) is not list or
        len([r for r in latest_rulesets if type(r) is dict and
             r.get("name") == RULESET_NAME]) != 1):
        raise CasDenied("CAS_RULESET_CHANGED_AFTER_WRITE")
    latest_detail = transport("GET", prefix + "/rulesets/" + str(matches[0]["id"]), None)
    _ruleset_ready([latest_detail])
    latest_master = transport("GET", prefix + "/branches/master", None)
    if (type(latest_master) is not dict or
        latest_master.get("protected") is not True or
        type(latest_master.get("commit")) is not dict or
        latest_master["commit"].get("sha") != master_sha):
        raise CasDenied("CAS_MASTER_CHANGED_AFTER_WRITE")
    return {
        "schema": "JM_GITHUB_NONCE_CAS_SYNTHETIC_RECEIPT_V1",
        "nonce": nonce,
        "public_claim_sha256": claim_sha256,
        "tag_object_sha": tag_sha,
        "tag_ref": "refs/tags/" + name,
        "head": master_sha,
        "exclusive_ref_create_observed": True,
        "global_nonrollback_proven": False,
        "product_gate": False,
    }
