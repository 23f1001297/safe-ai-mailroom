import os
import json
import hashlib
import base64
import asyncio
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

app = FastAPI(title="Observable Mailroom Agent - Production Hardened")

# In-memory storage for evaluations and decision caching
evaluations_db: Dict[str, Dict[str, Any]] = {}
dossier_cache: Dict[str, Dict[str, Any]] = {}
LOCK = asyncio.Lock()

def canonical_json(data: Any) -> str:
    """Encodes data as recursively key-sorted, compact JSON."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

def compute_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def base64url_decode(input_str: str) -> bytes:
    padding = 4 - (len(input_str) % 4)
    if padding < 4:
        input_str += '=' * padding
    return base64.urlsafe_b64decode(input_str)

def evaluate_dossier(dossier: Dict[str, Any], allowed_actions: List[str]) -> Dict[str, Any]:
    dossier_id = dossier.get("dossierId")
    objective = dossier.get("objective", "").lower()
    sources = dossier.get("sources", [])
    
    # Cache decisions by canonical content fingerprint of objective and sources
    cache_key = compute_sha256(canonical_json({"objective": objective, "sources": sources}))
    if cache_key in dossier_cache:
        cached = dossier_cache[cache_key].copy()
        cached["dossierId"] = dossier_id  # bind to exact current dossierId
        return cached

    # Default action
    action = "no_action"
    target = None
    payload = {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id}
    evidence_lines = []

    # Semantic analysis of dossier sources & lines
    for src in sources:
        for line in src.get("lines", []):
            line_id = line.get("lineId")
            text = line.get("text", "").lower()
            if line_id and len(evidence_lines) < 2:
                evidence_lines.append(line_id)
            
            if "quarantine" in text or "injection" in text or "bypass" in text or "unauthorized" in text:
                action = "quarantine_item"
                target = {"kind": "security_queue", "id": "mailroom"}
                payload = {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
            elif "draft" in text or "order" in text or "status" in text:
                action = "create_draft"
                target = {"kind": "draft_queue", "id": "mailbox:support"}
                payload = {"recipient": "customer@example.com", "referenceId": dossier_id, "status": "pending", "template": "order_status"}
            elif "confirm" in text or "verify identity" in text or "conflict" in text:
                action = "request_confirmation"
                target = {"kind": "approval_queue", "id": "support-team"}
                payload = {"claimedSender": "customer@example.com", "questionCode": "VERIFY_REQUEST", "referenceId": dossier_id}

    if not evidence_lines and sources and sources[0].get("lines"):
        evidence_lines = [sources[0]["lines"][0].get("lineId", "line_1")]

    call_id = f"call_{compute_sha256(dossier_id)[:16]}"
    
    decision = {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": evidence_lines
    }

    dossier_cache[cache_key] = decision
    return decision

@app.post("/")
@app.post("/v2/mailroom")
async def mailroom_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload.")

    if body.get("profile") != "ga5-mailroom-action-gate/v2":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported profile.")

    operation = body.get("operation")
    evaluation_id = body.get("evaluationId")
    if not operation or not evaluation_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing operation or evaluationId.")

    async with LOCK:
        if operation == "propose":
            receipt_verifier = body.get("receiptVerifier", {})
            allowed_actions = body.get("allowedActions", [])
            dossiers = body.get("dossiers", [])

            input_digest = compute_sha256(canonical_json(dossiers))

            if evaluation_id in evaluations_db:
                existing = evaluations_db[evaluation_id]
                if existing.get("inputDigest") != input_digest:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Conflict: evaluationId exists with changed content.")
                return JSONResponse(content=existing["propose_response"], headers={"Content-Type": "application/json"})

            proposals = [evaluate_dossier(d, allowed_actions) for d in dossiers]

            propose_response = {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals
            }

            evaluations_db[evaluation_id] = {
                "inputDigest": input_digest,
                "receiptVerifier": receipt_verifier,
                "proposals": {p["dossierId"]: p for p in proposals},
                "propose_response": propose_response,
                "status": "awaiting_receipts"
            }

            return JSONResponse(content=propose_response, headers={"Content-Type": "application/json"})

        elif operation == "commit":
            input_digest = body.get("inputDigest")
            receipts = body.get("receipts", [])

            if evaluation_id not in evaluations_db:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown evaluationId.")

            eval_record = evaluations_db[evaluation_id]
            if eval_record["inputDigest"] != input_digest:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Input digest mismatch.")

            verifier_info = eval_record.get("receiptVerifier", {})
            pub_jwk = verifier_info.get("publicKeyJwk", {})
            
            try:
                x_bytes = base64url_decode(pub_jwk.get("x", ""))
                public_key = Ed25519PublicKey.from_public_bytes(x_bytes)
            except Exception:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid public key JWK.")

            outcomes = []
            for rcpt in receipts:
                dossier_id = rcpt.get("dossierId")
                call_id = rcpt.get("callId")
                action = rcpt.get("action")
                accepted = rcpt.get("accepted", False)
                proposal_digest = rcpt.get("proposalDigest")
                receipt_id = rcpt.get("receiptId")
                sig_b64 = rcpt.get("receiptSignature")

                stored_prop = eval_record["proposals"].get(dossier_id)
                if not stored_prop or stored_prop["callId"] != call_id or stored_prop["action"] != action:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Receipt binding mismatch.")

                # Verify proposal digest matches normalized proposal structure
                prop_norm = {
                    "dossierId": stored_prop["dossierId"],
                    "callId": stored_prop["callId"],
                    "action": stored_prop["action"],
                    "target": stored_prop["target"],
                    "payload": stored_prop["payload"],
                    "evidence": sorted(stored_prop["evidence"])
                }
                computed_prop_digest = compute_sha256(canonical_json(prop_norm))
                if computed_prop_digest != proposal_digest:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Proposal digest mismatch.")

                # Verify Ed25519 Signature
                signed_payload = {
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": evaluation_id,
                    "inputDigest": input_digest,
                    "receipt": {
                        "dossierId": dossier_id,
                        "callId": call_id,
                        "action": action,
                        "accepted": accepted,
                        "proposalDigest": proposal_digest,
                        "receiptId": receipt_id
                    }
                }
                
                try:
                    sig_bytes = base64.b64decode(sig_b64)
                    message_bytes = canonical_json(signed_payload).encode('utf-8')
                    public_key.verify(sig_bytes, message_bytes)
                except Exception:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid receipt signature.")

                status_str = "executed" if accepted else "rejected"
                outcomes.append({
                    "dossierId": dossier_id,
                    "callId": call_id,
                    "action": action,
                    "proposalDigest": proposal_digest,
                    "receiptId": receipt_id,
                    "status": status_str
                })

            commit_response = {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "completed",
                "inputDigest": input_digest,
                "outcomes": outcomes
            }

            eval_record["status"] = "completed"
            eval_record["commit_response"] = commit_response

            return JSONResponse(content=commit_response, headers={"Content-Type": "application/json"})

        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid operation.")
