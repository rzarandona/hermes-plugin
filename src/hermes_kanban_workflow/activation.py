"""Fixture-only durable ten-stage activation service model.

The public in-process plugin never owns this authority.  This engine exists to
exercise the service-side contract and repository fixtures are non-production.
"""
from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest_text(value: str) -> str:
    return sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class StageContract:
    stage: int
    name: str
    owner: str
    reviewer_roles: frozenset[str]
    entry: str
    passed: str
    denial: str
    kill: str
    rollback: str

    @property
    def digest(self) -> str:
        return sha256(_canonical({
            "stage": self.stage, "name": self.name, "owner": self.owner,
            "reviewer_roles": sorted(self.reviewer_roles), "entry": self.entry,
            "passed": self.passed, "denial": self.denial, "kill": self.kill,
            "rollback": self.rollback,
        })).hexdigest()

    def evidence(self, kind: str) -> dict[str, object]:
        criterion = self.entry if kind == "entry" else self.passed
        return {
            "schema": f"activation-stage-{self.stage}-{kind}-v1",
            "contract_digest": self.digest,
            "criteria_digest": _digest_text(criterion),
            "kill_digest": _digest_text(self.kill),
            "rollback_digest": _digest_text(self.rollback),
            "thresholds_satisfied": True,
            "evidence_digest": _digest_text(f"{self.stage}:{kind}:{criterion}"),
        }


STAGE_CONTRACTS: tuple[StageContract, ...] = (
    StageContract(1, "Observe-only Watchdog and classifier", "Product Secretary", frozenset({"Watchdog reviewer", "classifier reviewer"}), "load receipt; exact compatibility; signed policy/trust; zero host mutation credentials", "seven authenticated observation days; no mutation; classifier and dedupe targets; retained evidence", "missing or altered evidence denies entry", "mutation path, secret exposure, alert storm, or evidence loss", "unregister observers; preserve ledger"),
    StageContract(2, "Dry-run guarded recommendations", "Gatekeeper", frozenset({"Guarded-service reviewer", "Auditor/Classifier reviewer"}), "stage-1 PASS; service identity/ACL/IPC; no effect authority", "100 representative commands; zero forbidden recommendation or durable mutation", "effect credential or unmatched recommendation denies", "external effect, direct write, stale policy, or divergence", "revoke dry-run capabilities; stage 1"),
    StageContract(3, "Enforced Flow 1 routing and direct-write denial", "Project PM", frozenset({"Flow 1 reviewer", "Security reviewer"}), "stage-2 PASS; sole-writer profile; wrong-product/protected cases; six-choice gate", "all Flow 1 cases; direct writes denied; exact owner receipts; no default authority", "missing identity, classification, choice, or ACL evidence denies", "misrouting, direct write, inferred approval, or cross-product mutation", "disable Flow 1 mutation; dry-run/observe-only"),
    StageContract(4, "Flow 2 R0 only", "Product Secretary", frozenset({"Recovery reviewer", "Gatekeeper"}), "stage-3 PASS; signed R0 and budget; fencing/resource tests; kill rehearsal", "all R0 commands pass 20 schedules; zero effect/scope expansion; read-back complete", "non-R0, unknown effect, exhausted budget, stale lease, or missing evidence denies", "outside-R0 write, duplicate effect, stale revival, or unreconciled state", "disable recovery; revoke capability; advance fencing"),
    StageContract(5, "Flow 2 allowlisted R1", "Gatekeeper", frozenset({"Recovery reviewer", "Effects reviewer"}), "stage-4 PASS; exact R1 registry; command idempotency; rollback rehearsal", "each R1 passes 20 failure schedules with one authoritative outcome", "unlisted/changed R1, missing proof, R2/R3/unknown, or stale evidence denies", "duplicate effect, unknown outcome, budget bypass, or registry mismatch", "revoke R1; stage 4 or lower"),
    StageContract(6, "Flow 3 non-production artifact and promotion controls", "Build and Release", frozenset({"Build reviewer", "Release reviewer", "Production Verifier"}), "stage-5 PASS; lower-trust root; registry/lanes; provenance and invalidation tests", "build-once identity and 20 non-production schedules; no production credential", "production target/root/secret, stale artifact, or missing provenance denies", "identity drift, signature failure, lane collision, or unreconciled promotion", "pause promotion; revoke capabilities; retain evidence"),
    StageContract(7, "Owner-authorized production release", "Operational Owner", frozenset({"Release Gatekeeper", "Independent Production Verifier"}), "stage-6 PASS; exact release approval; broker; progressive gates; drills; independent audit", "one exact progressive pilot; health/integrity/reconciliation/handoff evidence", "missing/expired/mismatched approval, secret, audit, verifier, or handoff denies", "threshold breach; collateral risk; non-reversible failure", "pause or preauthorized rollback; otherwise Owner decision"),
    StageContract(8, "Flow 4 observation and support classification", "Operational Owner", frozenset({"Incident reviewer", "Support reviewer"}), "stage-7 PASS; handoff; objectives/routes/alerts; read-only capability", "seven operational days; telemetry/journeys/integrity/support; zero mutation", "missing objective, owner, route, or read-only boundary denies", "unauthorized mutation, alert storm, missed critical signal, or evidence gap", "unregister Flow 4 observers; manual operations"),
    StageContract(9, "Preauthorized narrow operational commands", "Operational Owner", frozenset({"Operational-change reviewer", "Recovery reviewer", "Effects reviewer"}), "stage-8 PASS; reversible command registry; restore proof; leases; state machine", "every command passes 20 failure schedules; material change rejected; objectives met", "unlisted/material/irreversible/unknown/stale/unreconciled command denies", "material-change bypass, integrity loss, unknown effect, or restoration failure", "revoke operations; stage 8/manual control"),
    StageContract(10, "Owner-authorized retirement", "Operational Owner", frozenset({"Retirement reviewer", "Evidence Custodian", "Legal/Compliance verifier"}), "stage-9 PASS; exact retirement approval; inventories; legal clear; recovery; rehearsal", "exact retirement proves drain/migration/disposition/revocation/removal/archives/closure", "hold, unknown obligation, active dependency, failed disposition, missing archive, or stale approval denies", "new hold, consumer, traffic, integrity, or evidence issue", "execute recovery contract; remain open; fresh Owner approval"),
)


@dataclass(frozen=True)
class SignedActivationRecord:
    payload: Mapping[str, Any]
    key_id: str
    signature: str

    @property
    def digest(self) -> str:
        return sha256(_canonical(self.payload) + self.key_id.encode() + self.signature.encode()).hexdigest()


@dataclass(frozen=True)
class TrustEntry:
    public_key: bytes
    roles: frozenset[str]
    epoch: int
    revoked: bool = False

    @classmethod
    def from_private_key(cls, key: Ed25519PrivateKey, roles: set[str], epoch: int, *, revoked: bool = False) -> TrustEntry:
        return cls(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), frozenset(roles), epoch, revoked)


def sign_activation_record(payload: Mapping[str, Any], key_id: str, key: Ed25519PrivateKey) -> SignedActivationRecord:
    return SignedActivationRecord(dict(payload), key_id, base64.b64encode(key.sign(_canonical(payload))).decode("ascii"))


class ActivationTrustRegistry:
    def __init__(self, entries: Mapping[str, TrustEntry], *, minimum_epoch: int) -> None:
        self._entries = dict(entries)
        self.minimum_epoch = minimum_epoch

    def revoke(self, key_id: str) -> None:
        self._entries[key_id] = replace(self._entries[key_id], revoked=True)

    def rotate(self, key_id: str, entry: TrustEntry) -> None:
        if entry.epoch <= self.minimum_epoch:
            raise PermissionError("ACTIVATION_TRUST_ROLLBACK_DENIED")
        self._entries[key_id] = entry
        self.minimum_epoch = entry.epoch

    def verify(self, record: object, *, required_roles: frozenset[str]) -> SignedActivationRecord:
        if not isinstance(record, SignedActivationRecord):
            raise PermissionError("ACTIVATION_AUTHENTICATED_EVIDENCE_REQUIRED")
        entry = self._entries.get(record.key_id)
        if entry is None or entry.revoked:
            raise PermissionError("ACTIVATION_TRUST_REVOKED")
        if entry.epoch < self.minimum_epoch:
            raise PermissionError("ACTIVATION_TRUST_ROLLBACK_DENIED")
        if not required_roles <= entry.roles:
            raise PermissionError("ACTIVATION_REVIEWER_INELIGIBLE")
        try:
            Ed25519PublicKey.from_public_bytes(entry.public_key).verify(base64.b64decode(record.signature, validate=True), _canonical(record.payload))
        except (InvalidSignature, ValueError) as exc:
            raise PermissionError("ACTIVATION_SIGNATURE_INVALID") from exc
        return record


@dataclass(frozen=True)
class ActivationReceipt:
    stage: int
    receipt_digest: str
    predecessor_digest: str | None
    package_digest: str
    policy_digest: str
    host_digest: str
    plugin_version: str


@dataclass(frozen=True)
class ActivationDenial:
    stage: int | None
    code: str
    record_digests: tuple[str, ...]


class ActivationChain:
    """Service-side fixture engine; never a public production authority."""

    production_authority = False

    def __init__(self, package_digest: str, policy_digest: str, host_digest: str, plugin_version: str, trust: ActivationTrustRegistry, *, database: Path | None = None) -> None:
        self._identity = {"package_digest": package_digest, "policy_digest": policy_digest, "host_digest": host_digest, "plugin_version": plugin_version}
        self._trust = trust
        self._history: list[ActivationReceipt] = []
        self._current: ActivationReceipt | None = None
        self._used_nonces: set[str] = set()
        self.denials: list[ActivationDenial] = []
        self.agent_stage = 0
        self.desktop_stage = 0
        self._database = database
        if database is not None:
            self._open(database)

    def _open(self, database: Path) -> None:
        database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(database) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS activation_receipts(stage INTEGER PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS activation_nonces(nonce TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS activation_denials(sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS activation_state(id INTEGER PRIMARY KEY CHECK(id=1), stage INTEGER NOT NULL, receipt_digest TEXT);
            """)
            for (payload,) in conn.execute("SELECT payload FROM activation_receipts ORDER BY rowid"):
                self._history.append(ActivationReceipt(**json.loads(payload)))
            self._used_nonces = {row[0] for row in conn.execute("SELECT nonce FROM activation_nonces")}
            self.denials = [ActivationDenial(item["stage"], item["code"], tuple(item["record_digests"])) for (payload,) in conn.execute("SELECT payload FROM activation_denials ORDER BY sequence") for item in [json.loads(payload)]]
            row = conn.execute("SELECT stage, receipt_digest FROM activation_state WHERE id=1").fetchone()
            if row and row[0]:
                self._current = next(item for item in reversed(self._history) if item.receipt_digest == row[1])
                self.agent_stage = self._current.stage
                self.desktop_stage = self._current.stage if self._current.stage >= 8 else 0

    @property
    def current_stage(self) -> int:
        return self._current.stage if self._current else 0

    @property
    def history(self) -> tuple[ActivationReceipt, ...]:
        return tuple(self._history)

    def _record_denial(self, denial: ActivationDenial) -> None:
        self.denials.append(denial)
        if self._database is not None:
            with sqlite3.connect(self._database) as conn:
                conn.execute("INSERT INTO activation_denials(payload) VALUES (?)", (json.dumps({**asdict(denial), "record_digests": list(denial.record_digests)}, sort_keys=True),))

    def _deny(self, code: str, records: Sequence[object]) -> NoReturn:
        signed = [item for item in records if isinstance(item, SignedActivationRecord)]
        stages = [item.payload.get("stage") for item in signed if isinstance(item.payload.get("stage"), int)]
        self._record_denial(ActivationDenial(stages[0] if stages else None, code, tuple(item.digest for item in signed)))
        raise PermissionError(code)

    def _exact_record(self, record: SignedActivationRecord, *, kind: str, stage: int, predecessor: str | None, now: datetime, records: Sequence[object]) -> str:
        payload = record.payload
        try:
            expires = datetime.fromisoformat(str(payload.get("expires_at")))
        except ValueError:
            self._deny("ACTIVATION_STAGE_SKIP_DENIED", records)
        nonce = payload.get("nonce")
        exact = all(payload.get(k) == v for k, v in self._identity.items()) and payload.get("stage") == stage and payload.get("kind") == kind and payload.get("predecessor_digest") == predecessor and isinstance(nonce, str) and nonce not in self._used_nonces and expires > now
        if not exact:
            self._deny("ACTIVATION_STAGE_SKIP_DENIED", records)
        return str(nonce)

    def advance(self, *, entry: object, passed: object, review: object, owner: object, now: datetime) -> ActivationReceipt:
        review_values: list[object] = list(review.values()) if isinstance(review, Mapping) else ([*review] if isinstance(review, Sequence) and not isinstance(review, (str, bytes, SignedActivationRecord)) else [review])
        records = [entry, passed, *review_values, owner]
        try:
            if not isinstance(entry, SignedActivationRecord) or not isinstance(passed, SignedActivationRecord) or not isinstance(owner, SignedActivationRecord):
                self._deny("ACTIVATION_AUTHENTICATED_EVIDENCE_REQUIRED", records)
            stage_raw = entry.payload.get("stage")
            if not isinstance(stage_raw, int) or stage_raw != self.current_stage + 1 or not 1 <= stage_raw <= len(STAGE_CONTRACTS):
                self._deny("ACTIVATION_STAGE_SKIP_DENIED", records)
            stage = stage_raw
            contract = STAGE_CONTRACTS[stage - 1]
            verified_entry = self._trust.verify(entry, required_roles=frozenset({"Evidence Custodian"}))
            verified_passed = self._trust.verify(passed, required_roles=frozenset({"Evidence Custodian"}))
            verified_owner = self._trust.verify(owner, required_roles=frozenset({"Owner"}))
            if len(review_values) != len(contract.reviewer_roles):
                self._deny("ACTIVATION_ALL_REVIEWER_ROLES_REQUIRED", records)
            verified_reviews: list[SignedActivationRecord] = []
            for role in sorted(contract.reviewer_roles):
                candidates = [item for item in review_values if isinstance(item, SignedActivationRecord) and item.payload.get("reviewer_role") == role]
                if len(candidates) != 1:
                    self._deny("ACTIVATION_ALL_REVIEWER_ROLES_REQUIRED", records)
                verified_reviews.append(self._trust.verify(candidates[0], required_roles=frozenset({role})))
            if len({item.key_id for item in [*verified_reviews, verified_owner]}) != len(verified_reviews) + 1:
                self._deny("ACTIVATION_REVIEWER_INDEPENDENCE_DENIED", records)
            predecessor = self._current.receipt_digest if self._current else None
            nonces = [self._exact_record(verified_entry, kind="entry", stage=stage, predecessor=predecessor, now=now, records=records), self._exact_record(verified_passed, kind="pass", stage=stage, predecessor=predecessor, now=now, records=records)]
            for item in verified_reviews:
                nonces.append(self._exact_record(item, kind="review", stage=stage, predecessor=predecessor, now=now, records=records))
            nonces.append(self._exact_record(verified_owner, kind="owner-decision", stage=stage, predecessor=predecessor, now=now, records=records))
            if len(nonces) != len(set(nonces)):
                self._deny("ACTIVATION_STAGE_SKIP_DENIED", records)
            if verified_entry.payload.get("status") != "PASS" or verified_entry.payload.get("evidence") != contract.evidence("entry"):
                self._deny("ACTIVATION_GATE_EVIDENCE_SCHEMA_DENIED", records)
            if verified_passed.payload.get("status") != "PASS" or verified_passed.payload.get("evidence") != contract.evidence("pass"):
                self._deny("ACTIVATION_GATE_EVIDENCE_SCHEMA_DENIED", records)
            if any(item.payload.get("verdict") != "PASS" or item.payload.get("contract_digest") != contract.digest for item in verified_reviews):
                self._deny("ACTIVATION_INDEPENDENT_REVIEW_DENIED", records)
            if verified_owner.payload.get("decision") != f"ACTIVATE_STAGE_{stage}" or verified_owner.payload.get("contract_digest") != contract.digest:
                self._deny("ACTIVATION_OWNER_DECISION_DENIED", records)
            digest = sha256(_canonical({**self._identity, "stage": stage, "predecessor_digest": predecessor, "contract_digest": contract.digest, "records": [item.digest for item in [verified_entry, verified_passed, *verified_reviews, verified_owner]]})).hexdigest()
            receipt = ActivationReceipt(stage, digest, predecessor, **self._identity)
            if self._database is not None:
                with sqlite3.connect(self._database) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    for nonce in nonces:
                        conn.execute("INSERT INTO activation_nonces(nonce) VALUES (?)", (nonce,))
                    conn.execute("INSERT INTO activation_receipts(stage,payload) VALUES (?,?) ON CONFLICT(stage) DO UPDATE SET payload=excluded.payload", (stage, json.dumps(asdict(receipt), sort_keys=True)))
                    conn.execute("INSERT INTO activation_state(id,stage,receipt_digest) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET stage=excluded.stage,receipt_digest=excluded.receipt_digest", (stage, digest))
            self._used_nonces.update(nonces)
            self._history.append(receipt)
            self._current = receipt
            self.agent_stage = stage
            self.desktop_stage = stage if stage >= 8 else 0
            return receipt
        except PermissionError as exc:
            if not self.denials or self.denials[-1].record_digests != tuple(item.digest for item in records if isinstance(item, SignedActivationRecord)):
                self._deny(str(exc), records)
            raise

    def rollback(self, stage: int) -> ActivationReceipt | None:
        if stage < 0 or stage >= self.current_stage:
            raise ValueError("ACTIVATION_ROLLBACK_DENIED")
        self._current = next((item for item in reversed(self._history) if item.stage == stage), None)
        self.agent_stage = stage
        self.desktop_stage = stage if stage >= 8 else 0
        if self._database is not None:
            with sqlite3.connect(self._database) as conn:
                conn.execute("INSERT INTO activation_state(id,stage,receipt_digest) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET stage=excluded.stage,receipt_digest=excluded.receipt_digest", (stage, self._current.receipt_digest if self._current else None))
        return self._current
