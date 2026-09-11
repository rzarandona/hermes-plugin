from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from hermes_kanban_workflow.policy.model import PolicyDocument, VerifiedPolicy
from hermes_kanban_workflow.policy.verifier import PolicyVerificationError, TrustRoot


def load_verified_policy(
    path: str | Path,
    signature: bytes | str,
    trust_root: TrustRoot,
    *,
    now: datetime | None = None,
    last_known_compatible_digest: str | None = None,
    previous_policy: VerifiedPolicy | None = None,
) -> VerifiedPolicy:
    payload = Path(path).read_bytes()
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PolicyVerificationError("POLICY_SCHEMA_INVALID") from exc
    if isinstance(raw, dict) and raw.get("schema_version") not in (1,):
        raise PolicyVerificationError(
            "POLICY_VERSION_UNSUPPORTED",
            {"received": raw.get("schema_version"), "supported": [1]},
        )
    try:
        document = PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        raise PolicyVerificationError("POLICY_SCHEMA_INVALID") from exc

    trust_root.verify(signature, payload)
    if document.trust_epoch != trust_root.trust_epoch:
        code = (
            "POLICY_TRUST_EPOCH_ROLLBACK"
            if document.trust_epoch < trust_root.trust_epoch
            else "POLICY_TRUST_EPOCH_UNSUPPORTED"
        )
        raise PolicyVerificationError(
            code,
            {
                "policy_trust_epoch": document.trust_epoch,
                "current_trust_epoch": trust_root.trust_epoch,
            },
        )
    checked_at = now or datetime.now(UTC)
    if not document.issued_at <= checked_at < document.expires_at:
        code = "POLICY_EXPIRED" if checked_at >= document.expires_at else "POLICY_NOT_YET_EFFECTIVE"
        raise PolicyVerificationError(
            code,
            {
                "policy_digest": sha256(payload).hexdigest(),
                "last_known_compatible_digest": last_known_compatible_digest,
            },
        )
    if previous_policy is not None:
        prior = set(previous_policy.document.authority.effect_classes)
        added = sorted(set(document.authority.effect_classes) - prior)
        if added:
            raise PolicyVerificationError(
                "POLICY_AUTHORITY_WEAKENING", {"added_effect_classes": added}
            )
    return VerifiedPolicy(
        document=document,
        digest=sha256(payload).hexdigest(),
        signer_key_id=trust_root.key_id,
        signature=signature if isinstance(signature, bytes) else signature.encode(),
        verified_at=checked_at,
    )
