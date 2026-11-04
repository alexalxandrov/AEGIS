"""FastAPI endpoints for evidence handling.

The endpoints expose CRUD operations for evidence associated with findings.
They use the :class:`~aegis.evidence.EvidenceRepository` helper to interact
with the SQLite database.  The module is intentionally minimal – the goal is
to provide a usable API surface without adding external dependencies.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from ... import db, config
# create_app and analyst are not needed for the evidence router; they were
# mistakenly imported earlier. They are removed to avoid unused import
# warnings and potential circular import issues.

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])


class EvidenceIn(BaseModel):
    evidence_text: str


@router.get("/{finding_id}")
async def list_evidence(finding_id: int):
    c = db.connect()
    evidences = db.get_evidence(c, finding_id)
    return {"evidence": evidences}


@router.post("/{finding_id}")
async def add_evidence(finding_id: int, body: EvidenceIn):
    c = db.connect()
    evidence_id = db.store_evidence(c, finding_id, body.evidence_text)
    return {"evidence_id": evidence_id}
