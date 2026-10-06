from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException,
    Depends,
    Header,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl, Field

from datetime import datetime, timedelta, timezone
from collections import Counter
from urllib.parse import urlparse
from typing import Optional

import cv2
import hashlib
import io
import ipaddress
import joblib
import jwt
import math
import numpy as np
import os
import re
import secrets
import zipfile

from dotenv import load_dotenv
from supabase import create_client


# ==================================================
# CONFIGURATION
# ==================================================

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_TOKEN_SECRET = os.getenv("ADMIN_TOKEN_SECRET")


if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
    raise ValueError(
        "Supabase credentials missing. "
        "Check SUPABASE_URL and SUPABASE_SECRET_KEY."
    )

if not ADMIN_USERNAME or not ADMIN_PASSWORD or not ADMIN_TOKEN_SECRET:
    raise ValueError(
        "Admin credentials missing in .env."
    )

if len(ADMIN_TOKEN_SECRET) < 32:
    raise ValueError(
        "ADMIN_TOKEN_SECRET must be at least 32 characters."
    )


supabase = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY,
)


app = FastAPI(
    title="CyberShield AI API",
    description=(
        "AI-Based Cyber Threat Detection, "
        "Prevention & Awareness Platform"
    ),
    version="6.6.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://vaza4s.github.io",
        "https://vaza4s.github.io/CyberShield-AI",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


admin_security = HTTPBearer(
    auto_error=False
)


model = joblib.load(
    "url_model.pkl"
)


# ==================================================
# REQUEST MODELS
# ==================================================

class URLRequest(BaseModel):
    url: HttpUrl


class LoginRequest(BaseModel):
    user_identifier: str
    ip_address: str

    failed_attempts: int = Field(
        default=0,
        ge=0,
        le=1000,
    )

    new_device: bool = False
    unusual_location: bool = False

    login_hour: int = Field(
        ge=0,
        le=23,
    )


class EmailRequest(BaseModel):
    sender_email: str = Field(
        default="",
        max_length=320,
    )

    reply_to_email: Optional[str] = Field(
        default=None,
        max_length=320,
    )

    subject: str = Field(
        default="",
        max_length=1000,
    )

    body: str = Field(
        default="",
        max_length=100000,
    )


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class IncidentStatusRequest(BaseModel):
    status: str


# ==================================================
# COMMON HELPERS
# ==================================================

def utc_now():
    return datetime.now(
        timezone.utc
    )


def utc_now_iso():
    return utc_now().isoformat()


def clamp_score(value):
    return round(
        min(
            max(
                float(value or 0),
                0,
            ),
            100,
        ),
        2,
    )


def get_inserted_id(response):
    try:
        rows = response.data or []

        if rows and rows[0].get("id") is not None:
            return str(
                rows[0]["id"]
            )

    except Exception:
        pass

    return None


def get_inserted_int_id(response):
    value = get_inserted_id(
        response
    )

    try:
        if value is not None:
            return int(value)

    except (TypeError, ValueError):
        pass

    return None


def normalize_session_id(
    value: Optional[str]
):
    if not value:
        return None

    cleaned = re.sub(
        r"[^A-Za-z0-9._:-]",
        "-",
        value.strip(),
    )

    return cleaned[:120] or None


def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00",
            )
        )

    except Exception:
        return None


def safe_table_rows(
    table_name,
    columns="*",
):
    try:
        return (
            supabase
            .table(table_name)
            .select(columns)
            .execute()
            .data
            or []
        )

    except Exception as error:
        print(
            f"{table_name} Database Warning:",
            error,
        )

        return []


# ==================================================
# EXPLAINABILITY ENGINE
# ==================================================

def classify_explanation_category(
    reason: str
):
    text = reason.lower()

    if any(
        word in text
        for word in [
            "email",
            "sender",
            "reply-to",
            "reply to",
            "subject",
            "credential",
            "payment",
            "urgent",
            "message",
            "account threat",
            "suspension",
            "reward lure",
        ]
    ):
        return "email_content"

    if any(
        word in text
        for word in [
            "login",
            "device",
            "location",
            "failed",
            "time period",
        ]
    ):
        return "identity_behavior"

    if any(
        word in text
        for word in [
            "executable",
            "file extension",
            "signature",
            "archive",
            "pdf",
            "entropy",
            "script",
            "command",
            "content type",
        ]
    ):
        return "file_behavior"

    if any(
        word in text
        for word in [
            "keyword",
            "phishing",
            "domain",
            "subdomain",
            "punycode",
            "url",
            "https",
            "ip address",
            "hyphen",
            "digits",
            "link",
        ]
    ):
        return "url_structure"

    if "trusted" in text:
        return "trust_signal"

    return "security_signal"


def classify_explanation_severity(
    reason: str,
    risk_level: str,
):
    text = reason.lower()

    if "trusted" in text:
        return "positive"

    strong_terms = [
        "executable",
        "malicious",
        "very high",
        "dangerous",
        "punycode",
        "ip address",
        "multiple phishing",
        "unusual location",
        "hides executable",
        "credential",
        "reply-to",
        "high-risk url",
    ]

    if any(
        term in text
        for term in strong_terms
    ):
        return "high"

    if risk_level == "HIGH":
        return "high"

    if risk_level == "MEDIUM":
        return "medium"

    return "low"


def build_explainability(
    module,
    risk_level,
    reasons,
    *,
    ml_probability=None,
    heuristic_score=None,
    indicators=None,
):
    items = []

    for reason in reasons or []:
        items.append({
            "title":
                reason,

            "category":
                classify_explanation_category(
                    reason
                ),

            "severity":
                classify_explanation_severity(
                    reason,
                    risk_level,
                ),
        })

    for indicator in indicators or []:
        exists = any(
            item.get("title") == indicator
            for item in items
        )

        if not exists:
            items.append({
                "title":
                    indicator,

                "category":
                    classify_explanation_category(
                        indicator
                    ),

                "severity":
                    classify_explanation_severity(
                        indicator,
                        risk_level,
                    ),
            })

    if (
        module == "url"
        and
        ml_probability is not None
    ):
        if ml_probability >= 70:
            items.append({
                "title":
                    "ML model detected strong "
                    "phishing-like URL patterns",

                "category":
                    "machine_learning",

                "severity":
                    "high",

                "value":
                    round(
                        float(
                            ml_probability
                        ),
                        2,
                    ),

                "unit":
                    "% model malicious probability",
            })

        elif ml_probability >= 40:
            items.append({
                "title":
                    "ML model detected some "
                    "phishing-like URL patterns",

                "category":
                    "machine_learning",

                "severity":
                    "medium",

                "value":
                    round(
                        float(
                            ml_probability
                        ),
                        2,
                    ),

                "unit":
                    "% model malicious probability",
            })

    if (
        module == "url"
        and
        heuristic_score is not None
        and
        heuristic_score > 0
    ):
        items.append({
            "title":
                "URL security rules contributed "
                "to the final assessment",

            "category":
                "security_rules",

            "severity":
                (
                    "high"
                    if heuristic_score >= 65
                    else
                    "medium"
                    if heuristic_score >= 30
                    else
                    "low"
                ),

            "value":
                round(
                    float(
                        heuristic_score
                    ),
                    2,
                ),

            "unit":
                "/100 heuristic score",
        })

    button_label = (
        "Why was this flagged?"
    )

    if module == "file":
        button_label = (
            "Why was this file flagged?"
        )

    elif module == "login":
        button_label = (
            "Why is this login risky?"
        )

    elif module == "email":
        button_label = (
            "Why was this email flagged?"
        )

    return {
        "available":
            bool(items),

        "button_label":
            button_label,

        "title":
            "Why this result was generated",

        "items":
            items,
    }


# ==================================================
# PREVENTION ENGINE
# ==================================================

def get_prevention_actions(
    module,
    risk_level,
    prediction,
):
    risk_level = (
        risk_level
        or "LOW"
    ).upper()

    if module == "url":

        if risk_level == "HIGH":
            return [
                {
                    "title":
                        "Do not open or revisit the link",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Do not enter passwords, OTPs, "
                        "card details or personal data",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Verify the domain through the "
                        "organisation's official website",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Report the suspicious URL",
                    "priority":
                        "medium",
                },
            ]

        if risk_level == "MEDIUM":
            return [
                {
                    "title":
                        "Verify the domain before continuing",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Avoid entering credentials until "
                        "the site is confirmed",
                    "priority":
                        "medium",
                },
            ]

        return [
            {
                "title":
                    "No strong threat indicators were detected, "
                    "but still verify unexpected links",
                "priority":
                    "low",
            }
        ]

    if module == "file":

        if risk_level == "HIGH":
            return [
                {
                    "title":
                        "Do not execute or open the file",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Quarantine or isolate the file if "
                        "your security software supports it",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Verify the sender or download source",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Use the SHA-256 fingerprint for "
                        "additional reputation checks",
                    "priority":
                        "medium",
                },
            ]

        if risk_level == "MEDIUM":
            return [
                {
                    "title":
                        "Do not execute the file until "
                        "the source is verified",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Review detected indicators "
                        "and the file signature",
                    "priority":
                        "medium",
                },
            ]

        return [
            {
                "title":
                    "Static analysis found no strong suspicious "
                    "indicators; keep normal file-safety practices",
                "priority":
                    "low",
            }
        ]

    if module == "login":

        if risk_level == "HIGH":
            return [
                {
                    "title":
                        "Block or challenge the login attempt",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Require multi-factor authentication",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "If the activity was not yours, "
                        "change the account password",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Review active account sessions",
                    "priority":
                        "medium",
                },
            ]

        if risk_level == "MEDIUM":
            return [
                {
                    "title":
                        "Require additional authentication",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Verify the device and location",
                    "priority":
                        "medium",
                },
            ]

        return [
            {
                "title":
                    "No strong suspicious login indicators "
                    "were detected; continue monitoring",
                "priority":
                    "low",
            }
        ]

    if module == "qr":

        if risk_level == "HIGH":
            return [
                {
                    "title":
                        "Do not open the decoded link",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Do not enter passwords, OTPs "
                        "or payment information",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Verify the destination domain",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Report or discard the suspicious QR code",
                    "priority":
                        "medium",
                },
            ]

        if risk_level == "MEDIUM":
            return [
                {
                    "title":
                        "Verify the decoded destination "
                        "before opening it",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Avoid entering credentials until "
                        "the destination is confirmed",
                    "priority":
                        "medium",
                },
            ]

        return [
            {
                "title":
                    "No strong URL threat indicators were detected; "
                    "still verify unexpected QR codes",
                "priority":
                    "low",
            }
        ]

    if module == "email":

        if risk_level == "HIGH":
            return [
                {
                    "title":
                        "Do not click links or open attachments "
                        "from this message",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Do not provide passwords, OTPs, "
                        "banking or payment information",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Verify the sender through an independent "
                        "trusted communication channel",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Report the message as suspected phishing",
                    "priority":
                        "medium",
                },
            ]

        if risk_level == "MEDIUM":
            return [
                {
                    "title":
                        "Verify the sender before responding",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Inspect embedded links before opening them",
                    "priority":
                        "high",
                },
                {
                    "title":
                        "Avoid sharing sensitive information "
                        "until the message is verified",
                    "priority":
                        "medium",
                },
            ]

        return [
            {
                "title":
                    "No strong phishing indicators were detected, "
                    "but unexpected messages should still be verified",
                "priority":
                    "low",
            }
        ]

    return []


# ==================================================
# SECURITY EVENT LAYER
# ==================================================

def log_security_event(
    *,
    event_type,
    source_table,
    source_id,
    title,
    resource,
    prediction,
    risk_level,
    risk_score,
    reasons,
    prevention_actions,
    metadata=None,
    actor_identifier=None,
    session_id=None,
    correlation_key=None,
):
    try:

        response = (
            supabase
            .table(
                "security_events"
            )
            .insert({
                "event_type":
                    event_type,

                "source_table":
                    source_table,

                "source_id":
                    source_id,

                "actor_identifier":
                    actor_identifier,

                "session_id":
                    session_id,

                "title":
                    title,

                "resource":
                    resource,

                "prediction":
                    prediction,

                "risk_level":
                    risk_level,

                "risk_score":
                    clamp_score(
                        risk_score
                    ),

                "reasons":
                    reasons
                    or [],

                "prevention_actions":
                    prevention_actions
                    or [],

                "metadata":
                    metadata
                    or {},

                "correlation_key":
                    correlation_key,
            })
            .execute()
        )

        return {
            "saved":
                True,

            "event_id":
                get_inserted_id(
                    response
                ),
        }

    except Exception as error:

        print(
            "Security Event Database Error:",
            error,
        )

        return {
            "saved":
                False,

            "event_id":
                None,
        }


# ==================================================
# INCIDENT CORRELATION ENGINE
# ==================================================

INCIDENT_CORRELATION_WINDOW_MINUTES = 30

INCIDENT_MIN_RISK_WITH_CONTEXT = 40

INCIDENT_MIN_RISK_STANDALONE = 70


def incident_severity_from_score(
    score
):
    score = float(
        score
        or 0
    )

    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def build_incident_code():

    return (
        "CS-"
        +
        utc_now().strftime(
            "%Y%m%d"
        )
        +
        "-"
        +
        secrets.token_hex(
            4
        ).upper()
    )


def build_incident_title(
    event_types
):
    clean_types = sorted({
        str(
            item
        ).lower()
        for item in event_types
        if item
    })

    if len(
        clean_types
    ) >= 2:
        return (
            "Correlated multi-signal "
            "security incident"
        )

    mapping = {
        "url":
            "Suspicious URL security incident",

        "file":
            "Suspicious file security incident",

        "login":
            "Suspicious login security incident",

        "qr":
            "Suspicious QR security incident",

        "email":
            "Suspicious email security incident",
    }

    if not clean_types:
        return (
            "CyberShield security incident"
        )

    return mapping.get(
        clean_types[0],
        "CyberShield security incident",
    )


def combine_prevention_actions(
    events
):
    combined = []
    seen = set()

    for event in events:

        actions = (
            event.get(
                "prevention_actions"
            )
            or []
        )

        for action in actions:

            if isinstance(
                action,
                dict,
            ):

                title = str(
                    action.get(
                        "title",
                        "",
                    )
                ).strip()

                priority = (
                    action.get(
                        "priority"
                    )
                    or
                    "medium"
                )

            else:

                title = str(
                    action
                ).strip()

                priority = (
                    "medium"
                )

            if (
                not title
                or
                title.lower()
                in seen
            ):
                continue

            seen.add(
                title.lower()
            )

            combined.append({
                "title":
                    title,

                "priority":
                    priority,
            })

            if len(
                combined
            ) >= 8:
                return combined

    return combined


def recalculate_incident(
    incident_id
):
    try:

        links = (
            supabase
            .table(
                "incident_events"
            )
            .select(
                "security_event_id"
            )
            .eq(
                "incident_id",
                incident_id,
            )
            .execute()
            .data
            or []
        )

        event_ids = [
            row[
                "security_event_id"
            ]
            for row in links
            if row.get(
                "security_event_id"
            )
            is not None
        ]

        if not event_ids:
            return None

        events = (
            supabase
            .table(
                "security_events"
            )
            .select(
                "id,event_type,title,resource,"
                "prediction,risk_level,risk_score,"
                "prevention_actions,created_at"
            )
            .in_(
                "id",
                event_ids,
            )
            .execute()
            .data
            or []
        )

        if not events:
            return None

        event_types = sorted({
            str(
                event.get(
                    "event_type",
                    "unknown",
                )
            ).lower()
            for event in events
        })

        scores = [
            float(
                event.get(
                    "risk_score"
                )
                or 0
            )
            for event in events
        ]

        incident_score = (
            clamp_score(
                max(
                    scores
                    or [0]
                )
                +
                max(
                    0,
                    len(
                        event_types
                    )
                    - 1,
                )
                * 8
                +
                min(
                    8,
                    max(
                        0,
                        len(
                            events
                        )
                        - 1,
                    )
                    * 2,
                )
            )
        )

        times = [
            event.get(
                "created_at"
            )
            for event in events
            if event.get(
                "created_at"
            )
        ]

        summary = (
            f"{len(events)} suspicious security "
            f"event{'s' if len(events) != 1 else ''} "
            f"correlated in the same security context. "
            f"Observed event types: "
            f"{', '.join(event_types)}."
        )

        payload = {
            "title":
                build_incident_title(
                    event_types
                ),

            "severity":
                incident_severity_from_score(
                    incident_score
                ),

            "event_count":
                len(
                    events
                ),

            "risk_score":
                incident_score,

            "summary":
                summary,

            "prevention_actions":
                combine_prevention_actions(
                    events
                ),

            "first_detected_at":
                (
                    min(
                        times
                    )
                    if times
                    else
                    utc_now_iso()
                ),

            "last_detected_at":
                (
                    max(
                        times
                    )
                    if times
                    else
                    utc_now_iso()
                ),

            "updated_at":
                utc_now_iso(),
        }

        rows = (
            supabase
            .table(
                "incidents"
            )
            .update(
                payload
            )
            .eq(
                "id",
                incident_id,
            )
            .execute()
            .data
            or []
        )

        return (
            rows[0]
            if rows
            else
            payload
        )

    except Exception as error:

        print(
            "Incident Recalculation Error:",
            error,
        )

        return None


def find_recent_incident(
    session_id=None,
    correlation_key=None,
):

    if (
        not session_id
        and
        not correlation_key
    ):
        return None

    cutoff = (
        utc_now()
        -
        timedelta(
            minutes=
                INCIDENT_CORRELATION_WINDOW_MINUTES
        )
    ).isoformat()

    try:

        lookups = [
            (
                "session_id",
                session_id,
            ),
            (
                "correlation_key",
                correlation_key,
            ),
        ]

        for (
            field,
            value,
        ) in lookups:

            if not value:
                continue

            rows = (
                supabase
                .table(
                    "incidents"
                )
                .select("*")
                .neq(
                    "status",
                    "RESOLVED",
                )
                .gte(
                    "last_detected_at",
                    cutoff,
                )
                .eq(
                    field,
                    value,
                )
                .order(
                    "last_detected_at",
                    desc=True,
                )
                .limit(1)
                .execute()
                .data
                or []
            )

            if rows:
                return rows[0]

    except Exception as error:

        print(
            "Incident Lookup Error:",
            error,
        )

    return None


def correlate_security_event(
    *,
    event_id,
    event_type,
    risk_level,
    risk_score,
    session_id=None,
    correlation_key=None,
    prevention_actions=None,
):

    if not event_id:

        return {
            "created_or_updated":
                False,

            "incident_id":
                None,

            "incident_code":
                None,

            "correlated":
                False,

            "reason":
                "Security event was not persisted.",
        }

    session_id = (
        normalize_session_id(
            session_id
        )
    )

    correlation_key = (
        str(
            correlation_key
        ).strip()[:160]
        if correlation_key
        else
        None
    )

    risk_score = (
        clamp_score(
            risk_score
        )
    )

    minimum_risk = (
        INCIDENT_MIN_RISK_WITH_CONTEXT
        if (
            session_id
            or
            correlation_key
        )
        else
        INCIDENT_MIN_RISK_STANDALONE
    )

    if risk_score < minimum_risk:

        return {
            "created_or_updated":
                False,

            "incident_id":
                None,

            "incident_code":
                None,

            "correlated":
                False,

            "reason":
                "Risk did not meet "
                "the incident threshold.",
        }

    try:

        incident = (
            find_recent_incident(
                session_id,
                correlation_key,
            )
        )

        created = False

        if incident:

            incident_id = int(
                incident[
                    "id"
                ]
            )

            incident_code = (
                incident.get(
                    "incident_code"
                )
            )

        else:

            incident_code = (
                build_incident_code()
            )

            response = (
                supabase
                .table(
                    "incidents"
                )
                .insert({
                    "incident_code":
                        incident_code,

                    "title":
                        build_incident_title(
                            [
                                event_type
                            ]
                        ),

                    "severity":
                        incident_severity_from_score(
                            risk_score
                        ),

                    "status":
                        "OPEN",

                    "correlation_key":
                        correlation_key,

                    "session_id":
                        session_id,

                    "event_count":
                        1,

                    "risk_score":
                        risk_score,

                    "summary":
                        "A suspicious security event "
                        "met the CyberShield incident threshold.",

                    "prevention_actions":
                        prevention_actions
                        or [],

                    "first_detected_at":
                        utc_now_iso(),

                    "last_detected_at":
                        utc_now_iso(),
                })
                .execute()
            )

            incident_id = (
                get_inserted_int_id(
                    response
                )
            )

            if incident_id is None:

                return {
                    "created_or_updated":
                        False,

                    "incident_id":
                        None,

                    "incident_code":
                        None,

                    "correlated":
                        False,

                    "reason":
                        "Incident record could not be created.",
                }

            created = True

        try:

            (
                supabase
                .table(
                    "incident_events"
                )
                .insert({
                    "incident_id":
                        incident_id,

                    "security_event_id":
                        int(
                            event_id
                        ),
                })
                .execute()
            )

        except Exception as link_error:

            print(
                "Incident Link Warning:",
                link_error,
            )

        updated = (
            recalculate_incident(
                incident_id
            )
        )

        return {
            "created_or_updated":
                True,

            "incident_id":
                incident_id,

            "incident_code":
                incident_code,

            "correlated":
                not created,

            "created":
                created,

            "risk_score":
                (
                    updated.get(
                        "risk_score"
                    )
                    if isinstance(
                        updated,
                        dict,
                    )
                    else
                    risk_score
                ),

            "severity":
                (
                    updated.get(
                        "severity"
                    )
                    if isinstance(
                        updated,
                        dict,
                    )
                    else
                    incident_severity_from_score(
                        risk_score
                    )
                ),
        }

    except Exception as error:

        print(
            "Threat Correlation Error:",
            error,
        )

        return {
            "created_or_updated":
                False,

            "incident_id":
                None,

            "incident_code":
                None,

            "correlated":
                False,

            "reason":
                "Threat correlation failed.",
        }


# ==================================================
# THREAT INTELLIGENCE ENGINE
# ==================================================

THREAT_INTELLIGENCE_MIN_RISK = 40

THREAT_INTELLIGENCE_SOURCE = (
    "cybershield_internal"
)


def normalize_indicator_value(
    indicator_type,
    value,
):

    if not value:
        return None

    indicator_type = (
        str(
            indicator_type
        )
        .strip()
        .lower()
    )

    value = (
        str(
            value
        )
        .strip()
    )

    if not value:
        return None

    if indicator_type in {
        "domain",
        "ip",
        "file_hash",
        "email",
    }:

        if indicator_type == "domain":

            return (
                value
                .lower()
                .rstrip(".")[:500]
            )

        return (
            value
            .lower()[:500]
        )

    if indicator_type == "url":

        try:

            parsed = (
                urlparse(
                    value
                )
            )

            scheme = (
                parsed.scheme
                or
                "https"
            ).lower()

            hostname = (
                parsed.hostname
                or ""
            ).lower()

            port = (
                f":{parsed.port}"
                if parsed.port
                else
                ""
            )

            path = (
                parsed.path
                or
                "/"
            )

            query = (
                f"?{parsed.query}"
                if parsed.query
                else
                ""
            )

            if hostname:

                return (
                    f"{scheme}://"
                    f"{hostname}"
                    f"{port}"
                    f"{path}"
                    f"{query}"
                )[:1000]

        except Exception:
            pass

        return value[:1000]

    return value[:1000]


def severity_rank(
    severity
):

    mapping = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return mapping.get(
        str(
            severity
        ).upper(),
        0,
    )


def stronger_severity(
    first,
    second,
):

    if (
        severity_rank(
            second
        )
        >
        severity_rank(
            first
        )
    ):

        return str(
            second
        ).upper()

    return str(
        first
    ).upper()


def upsert_threat_indicator(
    *,
    indicator_type,
    indicator_value,
    category,
    severity,
    risk_score,
    confidence=None,
    metadata=None,
):

    normalized = (
        normalize_indicator_value(
            indicator_type,
            indicator_value,
        )
    )

    if not normalized:

        return {
            "recorded":
                False,

            "reason":
                "Indicator value was empty.",
        }

    now = (
        utc_now_iso()
    )

    try:

        rows = (
            supabase
            .table(
                "threat_intelligence"
            )
            .select("*")
            .eq(
                "indicator_type",
                indicator_type,
            )
            .eq(
                "indicator_value",
                normalized,
            )
            .eq(
                "source",
                THREAT_INTELLIGENCE_SOURCE,
            )
            .limit(1)
            .execute()
            .data
            or []
        )

        if rows:

            current = (
                rows[0]
            )

            current_metadata = (
                current.get(
                    "metadata"
                )
                if isinstance(
                    current.get(
                        "metadata"
                    ),
                    dict,
                )
                else
                {}
            )

            payload = {
                "category":
                    category,

                "severity":
                    stronger_severity(
                        current.get(
                            "severity"
                        )
                        or
                        "LOW",
                        severity,
                    ),

                "risk_score":
                    clamp_score(
                        max(
                            float(
                                current.get(
                                    "risk_score"
                                )
                                or
                                0
                            ),
                            float(
                                risk_score
                                or
                                0
                            ),
                        )
                    ),

                "confidence":
                    (
                        round(
                            float(
                                confidence
                            ),
                            2,
                        )
                        if confidence
                        is not None
                        else
                        current.get(
                            "confidence"
                        )
                    ),

                "status":
                    "ACTIVE",

                "sighting_count":
                    int(
                        current.get(
                            "sighting_count"
                        )
                        or
                        0
                    )
                    + 1,

                "last_seen_at":
                    now,

                "metadata":
                    {
                        **current_metadata,
                        **(
                            metadata
                            or
                            {}
                        ),
                    },

                "updated_at":
                    now,
            }

            updated = (
                supabase
                .table(
                    "threat_intelligence"
                )
                .update(
                    payload
                )
                .eq(
                    "id",
                    current[
                        "id"
                    ],
                )
                .execute()
                .data
                or []
            )

            return {
                "recorded":
                    True,

                "created":
                    False,

                "indicator":
                    (
                        updated[0]
                        if updated
                        else
                        {
                            **current,
                            **payload,
                        }
                    ),
            }

        payload = {
            "indicator_type":
                indicator_type,

            "indicator_value":
                normalized,

            "category":
                category,

            "severity":
                str(
                    severity
                ).upper(),

            "risk_score":
                clamp_score(
                    risk_score
                ),

            "confidence":
                (
                    round(
                        float(
                            confidence
                        ),
                        2,
                    )
                    if confidence
                    is not None
                    else
                    None
                ),

            "source":
                THREAT_INTELLIGENCE_SOURCE,

            "status":
                "ACTIVE",

            "sighting_count":
                1,

            "first_seen_at":
                now,

            "last_seen_at":
                now,

            "metadata":
                metadata
                or {},

            "created_at":
                now,

            "updated_at":
                now,
        }

        created = (
            supabase
            .table(
                "threat_intelligence"
            )
            .insert(
                payload
            )
            .execute()
            .data
            or []
        )

        return {
            "recorded":
                True,

            "created":
                True,

            "indicator":
                (
                    created[0]
                    if created
                    else
                    payload
                ),
        }

    except Exception as error:

        print(
            "Threat Intelligence Database Error:",
            error,
        )

        return {
            "recorded":
                False,

            "reason":
                "Threat intelligence logging failed.",
        }


def record_threat_intelligence(
    *,
    event_type,
    prediction,
    risk_level,
    risk_score,
    resource=None,
    hostname=None,
    sha256=None,
    ip_address=None,
    confidence=None,
    security_event_id=None,
):

    risk_score = (
        clamp_score(
            risk_score
        )
    )

    if (
        str(
            risk_level
        ).upper()
        ==
        "LOW"
        or
        risk_score
        <
        THREAT_INTELLIGENCE_MIN_RISK
    ):

        return {
            "recorded":
                False,

            "indicators":
                [],

            "reason":
                "Only MEDIUM/HIGH threat observations "
                "enter internal threat intelligence.",
        }

    if event_type in {
        "url",
        "qr",
    }:

        category = (
            "phishing_or_malicious_url"
        )

    elif event_type == "file":

        category = (
            "suspicious_file"
        )

    elif event_type == "login":

        category = (
            "suspicious_login_source"
        )

    else:

        category = (
            "suspicious"
        )

    metadata = {
        "event_type":
            event_type,

        "prediction":
            prediction,

        "security_event_id":
            security_event_id,
    }

    candidates = []

    if event_type in {
        "url",
        "qr",
    }:

        if resource:

            candidates.append(
                (
                    "url",
                    resource,
                )
            )

        if hostname:

            candidates.append(
                (
                    "domain",
                    hostname,
                )
            )

    elif (
        event_type
        ==
        "file"
        and
        sha256
    ):

        candidates.append(
            (
                "file_hash",
                sha256,
            )
        )

    elif (
        event_type
        ==
        "login"
        and
        ip_address
    ):

        candidates.append(
            (
                "ip",
                ip_address,
            )
        )

    results = []

    for (
        indicator_type,
        indicator_value,
    ) in candidates:

        result = (
            upsert_threat_indicator(
                indicator_type=
                    indicator_type,

                indicator_value=
                    indicator_value,

                category=
                    category,

                severity=
                    risk_level,

                risk_score=
                    risk_score,

                confidence=
                    confidence,

                metadata=
                    metadata,
            )
        )

        if result.get(
            "recorded"
        ):

            results.append(
                result.get(
                    "indicator"
                )
            )

    return {
        "recorded":
            bool(
                results
            ),

        "indicators":
            results,

        "source":
            "CyberShield Internal",
    }


# ==================================================
# URL ENGINE
# ==================================================

TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "github.com",
    "wikipedia.org",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "linkedin.com",
    "instagram.com",
    "facebook.com",
    "stackoverflow.com",
    "openai.com",
    "cloudflare.com",
    "mozilla.org",
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
    "bank",
    "wallet",
    "payment",
    "signin",
    "reset",
    "paypal",
    "bonus",
    "free",
    "prize",
}


def get_hostname(
    url
):

    try:

        return (
            urlparse(
                url
            ).hostname
            or
            ""
        ).lower()

    except Exception:

        return ""


def is_ip_address(
    hostname
):

    try:

        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:

        return False


def is_trusted_domain(
    hostname
):

    return any(
        hostname
        ==
        domain
        or
        hostname.endswith(
            "."
            +
            domain
        )
        for domain
        in TRUSTED_DOMAINS
    )


def calculate_url_heuristic_score(
    url
):

    score = 0
    reasons = []

    parsed = (
        urlparse(
            url
        )
    )

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    path_query = (
        parsed.path
        +
        " "
        +
        parsed.query
    ).lower()

    if is_ip_address(
        hostname
    ):

        score += 35

        reasons.append(
            "IP address used instead of a normal domain"
        )

    if parsed.scheme == "http":

        score += 10

        reasons.append(
            "Connection does not use HTTPS"
        )

    if "@" in url:

        score += 20

        reasons.append(
            "@ symbol detected in URL"
        )

    if len(
        url
    ) > 150:

        score += 15

        reasons.append(
            "Very long URL detected"
        )

    elif len(
        url
    ) > 90:

        score += 8

        reasons.append(
            "Long URL detected"
        )

    dot_count = (
        hostname.count(
            "."
        )
    )

    if dot_count >= 4:

        score += 15

        reasons.append(
            "Excessive number of subdomains"
        )

    elif dot_count >= 3:

        score += 7

    hyphen_count = (
        hostname.count(
            "-"
        )
    )

    if hyphen_count >= 3:

        score += 15

        reasons.append(
            "Multiple hyphens detected in domain"
        )

    elif hyphen_count >= 1:

        score += 5

    keyword_hits = [
        keyword
        for keyword
        in SUSPICIOUS_KEYWORDS
        if (
            keyword
            in
            hostname
            or
            keyword
            in
            path_query
        )
    ]

    if len(
        keyword_hits
    ) >= 4:

        score += 30

        reasons.append(
            "Multiple phishing-related keywords detected"
        )

    elif len(
        keyword_hits
    ) >= 2:

        score += 20

        reasons.append(
            "Suspicious URL keywords detected"
        )

    elif len(
        keyword_hits
    ) == 1:

        score += 7

        reasons.append(
            "Suspicious keyword detected"
        )

    if "xn--" in hostname:

        score += 20

        reasons.append(
            "Punycode domain detected"
        )

    digit_count = len(
        re.findall(
            r"\d",
            hostname,
        )
    )

    if digit_count >= 6:

        score += 15

        reasons.append(
            "Large number of digits in domain"
        )

    return (
        min(
            score,
            100,
        ),
        reasons,
    )


def analyze_url_signals(
    url
):

    hostname = (
        get_hostname(
            url
        )
    )

    probabilities = (
        model.predict_proba(
            [
                url
            ]
        )[0]
    )

    classes = (
        model.classes_
    )

    probability_map = {
        str(
            classes[
                index
            ]
        ):
            round(
                float(
                    probabilities[
                        index
                    ]
                )
                *
                100,
                2,
            )
        for index
        in range(
            len(
                classes
            )
        )
    }

    ml_malicious = float(
        probability_map.get(
            "malicious",
            0,
        )
    )

    ml_safe = float(
        probability_map.get(
            "safe",
            0,
        )
    )

    (
        heuristic_score,
        heuristic_reasons,
    ) = (
        calculate_url_heuristic_score(
            url
        )
    )

    trusted = (
        is_trusted_domain(
            hostname
        )
    )

    if trusted:

        final_risk = round(
            min(
                25.0,
                3.0
                +
                heuristic_score
                *
                0.35,
            ),
            2,
        )

        if heuristic_score >= 45:

            final_risk = max(
                final_risk,
                40.0,
            )

            prediction = (
                "needs_review"
            )

            risk_level = (
                "MEDIUM"
            )

        else:

            prediction = (
                "safe"
            )

            risk_level = (
                "LOW"
            )

        reasons = [
            "Recognized trusted base domain",
            *heuristic_reasons,
        ]

        decision_source = (
            "Trusted Domain + Security Rules"
        )

    else:

        final_risk = round(
            ml_malicious
            *
            0.60
            +
            heuristic_score
            *
            0.40,
            2,
        )

        reasons = list(
            heuristic_reasons
        )

        if (
            is_ip_address(
                hostname
            )
            and
            heuristic_score >= 45
        ):

            final_risk = max(
                final_risk,
                75,
            )

        if heuristic_score >= 65:

            final_risk = max(
                final_risk,
                75,
            )

        if (
            ml_malicious >= 90
            and
            heuristic_score >= 20
        ):

            final_risk = max(
                final_risk,
                70,
            )

        if final_risk >= 70:

            prediction = (
                "malicious"
            )

            risk_level = (
                "HIGH"
            )

        elif final_risk >= 40:

            prediction = (
                "needs_review"
            )

            risk_level = (
                "MEDIUM"
            )

        else:

            prediction = (
                "safe"
            )

            risk_level = (
                "LOW"
            )

        decision_source = (
            "Hybrid ML + Security Rules"
        )

    final_risk = (
        clamp_score(
            final_risk
        )
    )

    safe_probability = round(
        100
        -
        final_risk,
        2,
    )

    if prediction == "safe":

        confidence = (
            safe_probability
        )

    elif prediction == "malicious":

        confidence = (
            final_risk
        )

    else:

        confidence = max(
            final_risk,
            safe_probability,
        )

    return {
        "url":
            url,

        "hostname":
            hostname,

        "prediction":
            prediction,

        "risk_level":
            risk_level,

        "confidence":
            round(
                float(
                    confidence
                ),
                2,
            ),

        "final_risk_score":
            final_risk,

        "probabilities": {
            "malicious":
                final_risk,

            "safe":
                safe_probability,
        },

        "ml_analysis": {
            "malicious_probability":
                ml_malicious,

            "safe_probability":
                ml_safe,
        },

        "heuristic_analysis": {
            "risk_score":
                heuristic_score,

            "reasons":
                heuristic_reasons,
        },

        "trusted_domain":
            trusted,

        "decision_source":
            decision_source,

        "reasons":
            reasons,
    }


# ==================================================
# IDENTITY SECURITY ENGINE
# ==================================================

IDENTITY_SCORE_WINDOW_DAYS = 30


def security_score_level(
    score
):

    score = float(
        score
        or
        0
    )

    if score >= 90:
        return "EXCELLENT"

    if score >= 75:
        return "GOOD"

    if score >= 60:
        return "FAIR"

    if score >= 40:
        return "POOR"

    return "CRITICAL"


def identity_recommendations(
    *,
    high_risk_events,
    medium_risk_events,
    failed_attempts_total,
    new_device_events,
    unusual_location_events,
):

    recommendations = []

    if high_risk_events > 0:

        recommendations.extend([
            {
                "title":
                    "Enable or enforce multi-factor authentication",
                "priority":
                    "high",
            },
            {
                "title":
                    "Review recent account sessions "
                    "and revoke suspicious sessions",
                "priority":
                    "high",
            },
            {
                "title":
                    "Change the password if any "
                    "high-risk login was unauthorized",
                "priority":
                    "high",
            },
        ])

    if unusual_location_events > 0:

        recommendations.append({
            "title":
                "Verify unusual locations before "
                "granting account access",
            "priority":
                "high",
        })

    if failed_attempts_total >= 5:

        recommendations.append({
            "title":
                "Use rate limiting, temporary lockout "
                "or additional authentication after "
                "repeated failed attempts",
            "priority":
                "medium",
        })

    if new_device_events > 0:

        recommendations.append({
            "title":
                "Require verification for new "
                "or previously unseen devices",
            "priority":
                "medium",
        })

    if (
        high_risk_events == 0
        and
        medium_risk_events == 0
        and
        failed_attempts_total < 5
        and
        new_device_events == 0
        and
        unusual_location_events == 0
    ):

        recommendations.append({
            "title":
                "Maintain MFA and continue "
                "monitoring login activity",
            "priority":
                "low",
        })

    unique = []
    seen = set()

    for item in recommendations:

        title = (
            item[
                "title"
            ]
        )

        if title.lower() in seen:
            continue

        seen.add(
            title.lower()
        )

        unique.append(
            item
        )

    return unique[:8]


def calculate_identity_security_score(
    actor_identifier
):

    actor_identifier = (
        str(
            actor_identifier
        )
        .strip()
    )

    if not actor_identifier:

        return {
            "calculated":
                False,

            "reason":
                "Actor identifier is empty.",
        }

    try:

        all_rows = (
            supabase
            .table(
                "login_scans"
            )
            .select("*")
            .eq(
                "user_identifier",
                actor_identifier,
            )
            .order(
                "created_at",
                desc=False,
            )
            .execute()
            .data
            or []
        )

        cutoff = (
            utc_now()
            -
            timedelta(
                days=
                    IDENTITY_SCORE_WINDOW_DAYS
            )
        )

        recent_rows = []

        for row in all_rows:

            created_at = (
                parse_datetime(
                    row.get(
                        "created_at"
                    )
                )
            )

            if (
                created_at is not None
                and
                created_at >= cutoff
            ):

                recent_rows.append(
                    row
                )

        if (
            all_rows
            and
            not recent_rows
            and
            all(
                not row.get(
                    "created_at"
                )
                for row
                in all_rows
            )
        ):

            recent_rows = list(
                all_rows
            )

        suspicious_logins = sum(
            1
            for row
            in recent_rows
            if row.get(
                "prediction"
            )
            ==
            "suspicious"
        )

        failed_attempts_total = sum(
            int(
                row.get(
                    "failed_attempts"
                )
                or
                0
            )
            for row
            in recent_rows
        )

        new_device_events = sum(
            1
            for row
            in recent_rows
            if bool(
                row.get(
                    "new_device"
                )
            )
        )

        unusual_location_events = sum(
            1
            for row
            in recent_rows
            if bool(
                row.get(
                    "unusual_location"
                )
            )
        )

        high_risk_events = sum(
            1
            for row
            in recent_rows
            if row.get(
                "risk_level"
            )
            ==
            "HIGH"
        )

        medium_risk_events = sum(
            1
            for row
            in recent_rows
            if row.get(
                "risk_level"
            )
            ==
            "MEDIUM"
        )

        factors = []

        total_penalty = (
            0.0
        )

        if high_risk_events > 0:

            deduction = min(
                high_risk_events
                *
                18,
                45,
            )

            total_penalty += (
                deduction
            )

            factors.append({
                "factor":
                    "High-risk login events",

                "count":
                    high_risk_events,

                "deduction":
                    deduction,
            })

        if medium_risk_events > 0:

            deduction = min(
                medium_risk_events
                *
                8,
                24,
            )

            total_penalty += (
                deduction
            )

            factors.append({
                "factor":
                    "Medium-risk login events",

                "count":
                    medium_risk_events,

                "deduction":
                    deduction,
            })

        if failed_attempts_total > 0:

            deduction = min(
                failed_attempts_total
                *
                1.5,
                25,
            )

            deduction = round(
                deduction,
                2,
            )

            total_penalty += (
                deduction
            )

            factors.append({
                "factor":
                    "Failed login attempts",

                "count":
                    failed_attempts_total,

                "deduction":
                    deduction,
            })

        if new_device_events > 0:

            deduction = min(
                new_device_events
                *
                4,
                12,
            )

            total_penalty += (
                deduction
            )

            factors.append({
                "factor":
                    "New-device login events",

                "count":
                    new_device_events,

                "deduction":
                    deduction,
            })

        if unusual_location_events > 0:

            deduction = min(
                unusual_location_events
                *
                10,
                30,
            )

            total_penalty += (
                deduction
            )

            factors.append({
                "factor":
                    "Unusual-location login events",

                "count":
                    unusual_location_events,

                "deduction":
                    deduction,
            })

        security_score = (
            clamp_score(
                100
                -
                total_penalty
            )
        )

        score_level = (
            security_score_level(
                security_score
            )
        )

        recommendations = (
            identity_recommendations(
                high_risk_events=
                    high_risk_events,

                medium_risk_events=
                    medium_risk_events,

                failed_attempts_total=
                    failed_attempts_total,

                new_device_events=
                    new_device_events,

                unusual_location_events=
                    unusual_location_events,
            )
        )

        timestamps = [
            row.get(
                "created_at"
            )
            for row
            in all_rows
            if row.get(
                "created_at"
            )
        ]

        first_seen_at = (
            min(
                timestamps
            )
            if timestamps
            else
            utc_now_iso()
        )

        last_seen_at = (
            max(
                timestamps
            )
            if timestamps
            else
            utc_now_iso()
        )

        payload = {
            "actor_identifier":
                actor_identifier,

            "security_score":
                security_score,

            "score_level":
                score_level,

            "observation_count":
                len(
                    recent_rows
                ),

            "total_login_events":
                len(
                    all_rows
                ),

            "suspicious_logins":
                suspicious_logins,

            "failed_attempts_total":
                failed_attempts_total,

            "new_device_events":
                new_device_events,

            "unusual_location_events":
                unusual_location_events,

            "high_risk_events":
                high_risk_events,

            "medium_risk_events":
                medium_risk_events,

            "factors":
                factors,

            "recommendations":
                recommendations,

            "first_seen_at":
                first_seen_at,

            "last_seen_at":
                last_seen_at,

            "last_calculated_at":
                utc_now_iso(),

            "updated_at":
                utc_now_iso(),
        }

        existing = (
            supabase
            .table(
                "security_scores"
            )
            .select(
                "id,created_at"
            )
            .eq(
                "actor_identifier",
                actor_identifier,
            )
            .limit(1)
            .execute()
            .data
            or []
        )

        if existing:

            response = (
                supabase
                .table(
                    "security_scores"
                )
                .update(
                    payload
                )
                .eq(
                    "id",
                    existing[0][
                        "id"
                    ],
                )
                .execute()
            )

        else:

            payload[
                "created_at"
            ] = (
                utc_now_iso()
            )

            response = (
                supabase
                .table(
                    "security_scores"
                )
                .insert(
                    payload
                )
                .execute()
            )

        rows = (
            response.data
            or []
        )

        stored = (
            rows[0]
            if rows
            else
            payload
        )

        return {
            "calculated":
                True,

            "window_days":
                IDENTITY_SCORE_WINDOW_DAYS,

            "score":
                stored,
        }

    except Exception as error:

        print(
            "Identity Security Score Error:",
            error,
        )

        return {
            "calculated":
                False,

            "reason":
                "Unable to calculate identity security score.",
        }


# ==================================================
# EMAIL ENGINE
# ==================================================

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    flags=re.IGNORECASE,
)


EMAIL_SIGNAL_GROUPS = [
    {
        "weight":
            20,

        "reason":
            "Credential or account-verification "
            "language detected",

        "terms": [
            "verify your account",
            "confirm your account",
            "confirm your identity",
            "verify identity",
            "login now",
            "log in now",
            "reset password",
            "password expired",
            "enter your password",
            "verify password",
            "one time password",
            "otp",
            "credential",
        ],
    },
    {
        "weight":
            12,

        "reason":
            "Urgent or time-pressure language detected",

        "terms": [
            "urgent",
            "immediately",
            "action required",
            "act now",
            "within 24 hours",
            "expires today",
            "final warning",
            "respond immediately",
        ],
    },
    {
        "weight":
            12,

        "reason":
            "Account threat or suspension "
            "language detected",

        "terms": [
            "account suspended",
            "account will be suspended",
            "account locked",
            "unusual activity",
            "security alert",
            "unauthorized login",
            "unauthorised login",
        ],
    },
    {
        "weight":
            12,

        "reason":
            "Financial or payment-related "
            "request detected",

        "terms": [
            "payment required",
            "payment failed",
            "bank account",
            "credit card",
            "debit card",
            "wire transfer",
            "bank transfer",
            "invoice attached",
            "refund",
            "billing issue",
        ],
    },
    {
        "weight":
            12,

        "reason":
            "Click, prize or reward lure "
            "language detected",

        "terms": [
            "click here",
            "click the link",
            "claim your prize",
            "you are a winner",
            "free gift",
            "claim reward",
            "limited offer",
            "download now",
        ],
    },
]


def normalize_email_address(
    value
):

    return (
        str(
            value
            or ""
        )
        .strip()
        .lower()
    )


def valid_email_format(
    value
):

    return bool(
        EMAIL_PATTERN.match(
            normalize_email_address(
                value
            )
        )
    )


def email_domain(
    value
):

    value = (
        normalize_email_address(
            value
        )
    )

    if "@" not in value:
        return ""

    return (
        value
        .split(
            "@",
            1,
        )[1]
        .rstrip(".")
    )


def extract_urls_from_text(
    text
):

    matches = (
        URL_PATTERN.findall(
            text
            or ""
        )
    )

    cleaned = []
    seen = set()

    for url in matches:

        url = (
            url.rstrip(
                ".,;:!?)]}>\"'"
            )
        )

        if (
            url
            and
            url not in seen
        ):

            seen.add(
                url
            )

            cleaned.append(
                url
            )

        if len(
            cleaned
        ) >= 20:

            break

    return cleaned


def analyze_email_signals(
    sender_email,
    reply_to_email,
    subject,
    body,
):

    sender_email = (
        normalize_email_address(
            sender_email
        )
    )

    reply_to_email = (
        normalize_email_address(
            reply_to_email
        )
    )

    subject = (
        subject
        or ""
    ).strip()

    body = (
        body
        or ""
    ).strip()

    combined_text = (
        subject
        +
        "\n"
        +
        body
    ).lower()

    risk_score = 0

    reasons = []

    suspicious_keywords = []

    if sender_email:

        if not valid_email_format(
            sender_email
        ):

            risk_score += 10

            reasons.append(
                "Sender email address format appears invalid"
            )

    else:

        risk_score += 5

        reasons.append(
            "Sender email address was not provided"
        )

    if reply_to_email:

        if not valid_email_format(
            reply_to_email
        ):

            risk_score += 10

            reasons.append(
                "Reply-To email address format appears invalid"
            )

        else:

            sender_domain = (
                email_domain(
                    sender_email
                )
            )

            reply_domain = (
                email_domain(
                    reply_to_email
                )
            )

            if (
                sender_domain
                and
                reply_domain
                and
                sender_domain
                !=
                reply_domain
            ):

                risk_score += 20

                reasons.append(
                    "Sender and Reply-To domains do not match"
                )

    for group in EMAIL_SIGNAL_GROUPS:

        matched_terms = [
            term
            for term
            in group[
                "terms"
            ]
            if term
            in combined_text
        ]

        if matched_terms:

            risk_score += (
                group[
                    "weight"
                ]
            )

            reasons.append(
                group[
                    "reason"
                ]
            )

            suspicious_keywords.extend(
                matched_terms
            )

            if len(
                matched_terms
            ) >= 3:

                risk_score += 4

    extracted_urls = (
        extract_urls_from_text(
            subject
            +
            "\n"
            +
            body
        )
    )

    url_analyses = []

    for url in extracted_urls[
        :5
    ]:

        try:

            result = (
                analyze_url_signals(
                    url
                )
            )

            url_analyses.append(
                result
            )

        except Exception as error:

            print(
                "Embedded URL Analysis Warning:",
                error,
            )

    if url_analyses:

        highest_url_risk = max(
            float(
                item.get(
                    "final_risk_score"
                )
                or
                0
            )
            for item
            in url_analyses
        )

        if highest_url_risk >= 70:

            risk_score += 38

            reasons.append(
                "Email contains a high-risk URL"
            )

        elif highest_url_risk >= 40:

            risk_score += 22

            reasons.append(
                "Email contains a suspicious URL"
            )

        elif highest_url_risk >= 20:

            risk_score += 5

            reasons.append(
                "Email contains a URL with minor risk signals"
            )

        suspicious_url_count = sum(
            1
            for item
            in url_analyses
            if float(
                item.get(
                    "final_risk_score"
                )
                or
                0
            )
            >=
            40
        )

        if suspicious_url_count >= 2:

            risk_score += 8

            reasons.append(
                "Multiple suspicious links were detected"
            )

    if len(
        extracted_urls
    ) >= 5:

        risk_score += 6

        reasons.append(
            "Email contains many external links"
        )

    risk_score = (
        clamp_score(
            risk_score
        )
    )

    if risk_score >= 70:

        risk_level = (
            "HIGH"
        )

        prediction = (
            "suspicious"
        )

    elif risk_score >= 40:

        risk_level = (
            "MEDIUM"
        )

        prediction = (
            "needs_review"
        )

    else:

        risk_level = (
            "LOW"
        )

        prediction = (
            "safe"
        )

    return {
        "sender_email":
            sender_email,

        "reply_to_email":
            (
                reply_to_email
                or
                None
            ),

        "subject":
            subject,

        "extracted_urls":
            extracted_urls,

        "suspicious_keywords":
            sorted(
                set(
                    suspicious_keywords
                )
            ),

        "url_analyses":
            url_analyses,

        "prediction":
            prediction,

        "risk_level":
            risk_level,

        "risk_score":
            risk_score,

        "reasons":
            reasons,
    }


def record_email_threat_intelligence(
    *,
    sender_email,
    email_result,
    security_event_id,
):

    risk_score = float(
        email_result.get(
            "risk_score"
        )
        or
        0
    )

    risk_level = (
        email_result.get(
            "risk_level"
        )
        or
        "LOW"
    )

    if (
        risk_level
        ==
        "LOW"
        or
        risk_score
        <
        40
    ):

        return {
            "recorded":
                False,

            "indicators":
                [],

            "reason":
                "LOW-risk email observations are not "
                "added to threat intelligence.",
        }

    results = []

    if (
        sender_email
        and
        valid_email_format(
            sender_email
        )
    ):

        sender_result = (
            upsert_threat_indicator(
                indicator_type=
                    "email",

                indicator_value=
                    sender_email,

                category=
                    "suspicious_email_sender",

                severity=
                    risk_level,

                risk_score=
                    risk_score,

                metadata={
                    "event_type":
                        "email",

                    "security_event_id":
                        security_event_id,

                    "subject":
                        email_result.get(
                            "subject",
                            "",
                        )[:200],
                },
            )
        )

        if sender_result.get(
            "recorded"
        ):

            results.append(
                sender_result.get(
                    "indicator"
                )
            )

    for url_result in (
        email_result.get(
            "url_analyses"
        )
        or []
    ):

        url_risk = float(
            url_result.get(
                "final_risk_score"
            )
            or
            0
        )

        if url_risk < 40:
            continue

        for (
            indicator_type,
            indicator_value,
        ) in [
            (
                "url",
                url_result.get(
                    "url"
                ),
            ),
            (
                "domain",
                url_result.get(
                    "hostname"
                ),
            ),
        ]:

            if not indicator_value:
                continue

            indicator_result = (
                upsert_threat_indicator(
                    indicator_type=
                        indicator_type,

                    indicator_value=
                        indicator_value,

                    category=
                        "email_embedded_threat",

                    severity=
                        url_result.get(
                            "risk_level"
                        )
                        or
                        "MEDIUM",

                    risk_score=
                        url_risk,

                    confidence=
                        url_result.get(
                            "confidence"
                        ),

                    metadata={
                        "event_type":
                            "email",

                        "security_event_id":
                            security_event_id,

                        "sender_email":
                            sender_email,
                    },
                )
            )

            if indicator_result.get(
                "recorded"
            ):

                results.append(
                    indicator_result.get(
                        "indicator"
                    )
                )

    return {
        "recorded":
            bool(
                results
            ),

        "indicators":
            results,

        "source":
            "CyberShield Internal",
    }


# ==================================================
# QR HELPERS
# ==================================================

def extract_url_from_qr_content(
    content
):

    value = (
        content
        or ""
    ).strip()

    if not value:
        return None

    lower = (
        value.lower()
    )

    if (
        lower.startswith(
            "http://"
        )
        or
        lower.startswith(
            "https://"
        )
    ):

        candidate = (
            value
        )

    elif lower.startswith(
        "www."
    ):

        candidate = (
            "https://"
            +
            value
        )

    elif re.match(
        r"^[a-z0-9.-]+\.[a-z]{2,}"
        r"([/:?#].*)?$",
        value,
        flags=re.IGNORECASE,
    ):

        candidate = (
            "https://"
            +
            value
        )

    else:

        return None

    try:

        parsed = (
            urlparse(
                candidate
            )
        )

        if (
            parsed.scheme
            in {
                "http",
                "https",
            }
            and
            parsed.hostname
        ):

            return (
                candidate
            )

    except Exception:
        pass

    return None


# ==================================================
# FILE HELPERS
# ==================================================

def calculate_entropy(
    data
):

    if not data:

        return 0.0

    counts = (
        Counter(
            data
        )
    )

    length = len(
        data
    )

    entropy = 0.0

    for count in counts.values():

        probability = (
            count
            /
            length
        )

        entropy -= (
            probability
            *
            math.log2(
                probability
            )
        )

    return round(
        entropy,
        3,
    )


def get_file_type_information(
    content
):

    if content.startswith(
        b"%PDF"
    ):

        return (
            "application/pdf",
            "PDF document",
        )

    if content.startswith(
        b"PK\x03\x04"
    ):

        return (
            "application/zip",
            "ZIP-based file",
        )

    if content.startswith(
        b"MZ"
    ):

        return (
            "application/x-msdownload",
            "Windows executable",
        )

    if content.startswith(
        b"\x7fELF"
    ):

        return (
            "application/x-executable",
            "Linux executable",
        )

    macho_signatures = [
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    ]

    for signature in macho_signatures:

        if content.startswith(
            signature
        ):

            return (
                "application/x-mach-binary",
                "macOS Mach-O executable",
            )

    if content.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):

        return (
            "image/png",
            "PNG image",
        )

    if content.startswith(
        b"\xff\xd8\xff"
    ):

        return (
            "image/jpeg",
            "JPEG image",
        )

    if (
        content.startswith(
            b"GIF87a"
        )
        or
        content.startswith(
            b"GIF89a"
        )
    ):

        return (
            "image/gif",
            "GIF image",
        )

    try:

        content[
            :4096
        ].decode(
            "utf-8"
        )

        return (
            "text/plain",
            "Text file",
        )

    except UnicodeDecodeError:

        return (
            "application/octet-stream",
            "Generic binary file",
        )


def detect_file_signature(
    content
):

    if content.startswith(
        b"MZ"
    ):

        return (
            "Windows PE executable"
        )

    if content.startswith(
        b"\x7fELF"
    ):

        return (
            "Linux ELF executable"
        )

    if content.startswith(
        b"%PDF"
    ):

        return (
            "PDF document"
        )

    if content.startswith(
        b"PK\x03\x04"
    ):

        return (
            "ZIP archive"
        )

    macho_signatures = [
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    ]

    for signature in macho_signatures:

        if content.startswith(
            signature
        ):

            return (
                "Mach-O executable"
            )

    if content.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):

        return (
            "PNG image"
        )

    if content.startswith(
        b"\xff\xd8\xff"
    ):

        return (
            "JPEG image"
        )

    return (
        "Unknown / generic"
    )


def scan_text_patterns(
    content
):

    text = (
        content[
            :2 * 1024 * 1024
        ]
        .decode(
            "utf-8",
            errors="ignore",
        )
        .lower()
    )

    patterns = {
        "powershell":
            "PowerShell reference detected",

        "cmd.exe":
            "Windows command shell reference detected",

        "wscript":
            "Windows Script Host reference detected",

        "cscript":
            "Windows script execution reference detected",

        "invoke-expression":
            "PowerShell Invoke-Expression detected",

        "frombase64string":
            "Base64 decoding behavior detected",

        "downloadstring":
            "Remote download behavior detected",

        "eval(":
            "Dynamic code execution pattern detected",

        "os.system(":
            "Operating system command execution detected",

        "subprocess":
            "Process execution reference detected",

        "chmod +x":
            "Executable permission modification detected",

        "curl http":
            "Remote download command detected",

        "wget http":
            "Remote download command detected",
    }

    return [
        description
        for (
            pattern,
            description,
        ) in patterns.items()
        if pattern in text
    ]


def scan_pdf(
    content
):

    patterns = {
        b"/JavaScript":
            "Embedded PDF JavaScript detected",

        b"/JS":
            "PDF JavaScript reference detected",

        b"/OpenAction":
            "PDF automatic OpenAction detected",

        b"/Launch":
            "PDF launch action detected",

        b"/AA":
            "PDF automatic action detected",
    }

    return [
        description
        for (
            pattern,
            description,
        ) in patterns.items()
        if pattern in content
    ]


def scan_zip(
    content
):

    indicators = []
    suspicious_inside = []

    dangerous_extensions = [
        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".msi",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".dll",
        ".com",
    ]

    try:

        archive = (
            zipfile.ZipFile(
                io.BytesIO(
                    content
                )
            )
        )

        for member in (
            archive.infolist()[
                :2000
            ]
        ):

            filename = (
                member.filename
                .lower()
            )

            if any(
                filename.endswith(
                    extension
                )
                for extension
                in dangerous_extensions
            ):

                suspicious_inside.append(
                    member.filename
                )

            if (
                member.compress_size > 0
                and
                member.file_size
                >
                5 * 1024 * 1024
            ):

                compression_ratio = (
                    member.file_size
                    /
                    member.compress_size
                )

                if compression_ratio > 100:

                    indicators.append(
                        "Very high archive compression ratio detected"
                    )

        if suspicious_inside:

            indicators.append(
                "Archive contains potentially dangerous files"
            )

    except (
        zipfile.BadZipFile,
        RuntimeError,
    ):

        indicators.append(
            "Archive structure could not be validated"
        )

    return (
        indicators,
        suspicious_inside[:20],
    )


# ==================================================
# URL REPUTATION ENGINE
# ==================================================

def query_url_reputation(
    url
):

    hostname = (
        get_hostname(
            url
        )
    )

    normalized_url = (
        normalize_indicator_value(
            "url",
            url,
        )
    )

    normalized_domain = (
        normalize_indicator_value(
            "domain",
            hostname,
        )
    )

    matches = []

    try:

        if normalized_url:

            rows = (
                supabase
                .table(
                    "threat_intelligence"
                )
                .select("*")
                .eq(
                    "indicator_type",
                    "url",
                )
                .eq(
                    "indicator_value",
                    normalized_url,
                )
                .eq(
                    "source",
                    THREAT_INTELLIGENCE_SOURCE,
                )
                .execute()
                .data
                or []
            )

            matches.extend(
                rows
            )

        if normalized_domain:

            rows = (
                supabase
                .table(
                    "threat_intelligence"
                )
                .select("*")
                .eq(
                    "indicator_type",
                    "domain",
                )
                .eq(
                    "indicator_value",
                    normalized_domain,
                )
                .eq(
                    "source",
                    THREAT_INTELLIGENCE_SOURCE,
                )
                .execute()
                .data
                or []
            )

            matches.extend(
                rows
            )

    except Exception as error:

        print(
            "URL Reputation Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to check URL reputation"
            ),
        )

    if not matches:

        return {
            "known":
                False,

            "classification":
                "UNKNOWN",

            "url":
                url,

            "hostname":
                hostname,

            "message":
                "No CyberShield internal "
                "threat-intelligence record exists. "
                "Unknown does not mean safe.",

            "source":
                "CyberShield Internal",

            "indicators":
                [],
        }

    highest = max(
        matches,
        key=lambda row: (
            severity_rank(
                row.get(
                    "severity"
                )
                or
                "LOW"
            ),
            float(
                row.get(
                    "risk_score"
                )
                or
                0
            ),
        ),
    )

    return {
        "known":
            True,

        "classification":
            highest.get(
                "severity"
            ),

        "risk_score":
            highest.get(
                "risk_score"
            ),

        "category":
            highest.get(
                "category"
            ),

        "url":
            url,

        "hostname":
            hostname,

        "sighting_count":
            sum(
                int(
                    row.get(
                        "sighting_count"
                    )
                    or
                    0
                )
                for row
                in matches
            ),

        "first_seen_at":
            min(
                [
                    row[
                        "first_seen_at"
                    ]
                    for row
                    in matches
                    if row.get(
                        "first_seen_at"
                    )
                ],
                default=None,
            ),

        "last_seen_at":
            max(
                [
                    row[
                        "last_seen_at"
                    ]
                    for row
                    in matches
                    if row.get(
                        "last_seen_at"
                    )
                ],
                default=None,
            ),

        "source":
            "CyberShield Internal",

        "indicators":
            matches,
    }


# ==================================================
# REPORT ENGINE
# ==================================================

REPORT_MAX_DAYS = 365


def validate_report_days(
    days
):

    try:

        days = int(
            days
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail=(
                "days must be an integer"
            ),
        )

    if (
        days < 1
        or
        days > REPORT_MAX_DAYS
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "days must be between "
                "1 and 365"
            ),
        )

    return days


def filter_rows_by_time(
    rows,
    field,
    cutoff,
):

    filtered = []

    for row in rows:

        dt = (
            parse_datetime(
                row.get(
                    field
                )
            )
        )

        if (
            dt is not None
            and
            dt >= cutoff
        ):

            filtered.append(
                row
            )

    return filtered


def build_daily_series(
    rows,
    date_field,
    days,
):

    today = (
        utc_now()
        .date()
    )

    start_date = (
        today
        -
        timedelta(
            days=
                days
                -
                1
        )
    )

    counts = {}

    for offset in range(
        days
    ):

        date_value = (
            start_date
            +
            timedelta(
                days=
                    offset
            )
        )

        counts[
            date_value.isoformat()
        ] = 0

    for row in rows:

        dt = (
            parse_datetime(
                row.get(
                    date_field
                )
            )
        )

        if dt is None:
            continue

        date_key = (
            dt.date()
            .isoformat()
        )

        if date_key in counts:

            counts[
                date_key
            ] += 1

    return [
        {
            "date":
                date_key,

            "count":
                counts[
                    date_key
                ],
        }
        for date_key
        in sorted(
            counts.keys()
        )
    ]


def count_field_values(
    rows,
    field,
    allowed_values=None,
):

    counts = {}

    if allowed_values:

        for value in allowed_values:

            counts[
                value
            ] = 0

    for row in rows:

        value = (
            row.get(
                field
            )
        )

        if value is None:
            continue

        value = str(
            value
        )

        counts[
            value
        ] = (
            counts.get(
                value,
                0,
            )
            +
            1
        )

    return counts


def report_top_indicators(
    indicators,
    limit=10,
    indicator_types=None,
):

    rows = (
        indicators
    )

    if indicator_types:

        rows = [
            row
            for row
            in rows
            if row.get(
                "indicator_type"
            )
            in
            indicator_types
        ]

    rows = sorted(
        rows,
        key=lambda row: (
            int(
                row.get(
                    "sighting_count"
                )
                or
                0
            ),
            float(
                row.get(
                    "risk_score"
                )
                or
                0
            ),
            severity_rank(
                row.get(
                    "severity"
                )
                or
                "LOW"
            ),
        ),
        reverse=True,
    )

    return rows[
        :limit
    ]


def build_security_report(
    days
):

    days = (
        validate_report_days(
            days
        )
    )

    report_end = (
        utc_now()
    )

    report_start = (
        report_end
        -
        timedelta(
            days=
                days
        )
    )

    all_security_events = (
        safe_table_rows(
            "security_events"
        )
    )

    all_incidents = (
        safe_table_rows(
            "incidents"
        )
    )

    all_threat_intel = (
        safe_table_rows(
            "threat_intelligence"
        )
    )

    url_scans = (
        safe_table_rows(
            "url_scans"
        )
    )

    file_scans = (
        safe_table_rows(
            "file_scans"
        )
    )

    login_scans = (
        safe_table_rows(
            "login_scans"
        )
    )

    qr_scans = (
        safe_table_rows(
            "qr_scans"
        )
    )

    email_scans = (
        safe_table_rows(
            "email_scans"
        )
    )

    security_scores = (
        safe_table_rows(
            "security_scores"
        )
    )

    security_events = (
        filter_rows_by_time(
            all_security_events,
            "created_at",
            report_start,
        )
    )

    incidents = (
        filter_rows_by_time(
            all_incidents,
            "last_detected_at",
            report_start,
        )
    )

    threat_intel = (
        filter_rows_by_time(
            all_threat_intel,
            "last_seen_at",
            report_start,
        )
    )

    url_scans = (
        filter_rows_by_time(
            url_scans,
            "created_at",
            report_start,
        )
    )

    file_scans = (
        filter_rows_by_time(
            file_scans,
            "created_at",
            report_start,
        )
    )

    login_scans = (
        filter_rows_by_time(
            login_scans,
            "created_at",
            report_start,
        )
    )

    qr_scans = (
        filter_rows_by_time(
            qr_scans,
            "created_at",
            report_start,
        )
    )

    email_scans = (
        filter_rows_by_time(
            email_scans,
            "created_at",
            report_start,
        )
    )

    event_type_breakdown = (
        count_field_values(
            security_events,
            "event_type",
            [
                "url",
                "file",
                "login",
                "qr",
                "email",
            ],
        )
    )

    risk_breakdown = (
        count_field_values(
            security_events,
            "risk_level",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
            ],
        )
    )

    incident_severity = (
        count_field_values(
            incidents,
            "severity",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ],
        )
    )

    incident_status = (
        count_field_values(
            incidents,
            "status",
            [
                "OPEN",
                "INVESTIGATING",
                "RESOLVED",
            ],
        )
    )

    indicator_type_breakdown = (
        count_field_values(
            threat_intel,
            "indicator_type",
            [
                "url",
                "domain",
                "ip",
                "file_hash",
                "email",
            ],
        )
    )

    indicator_severity = (
        count_field_values(
            threat_intel,
            "severity",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ],
        )
    )

    total_scans = (
        len(
            url_scans
        )
        +
        len(
            file_scans
        )
        +
        len(
            login_scans
        )
        +
        len(
            qr_scans
        )
        +
        len(
            email_scans
        )
    )

    high_medium_events = sum(
        1
        for row
        in security_events
        if row.get(
            "risk_level"
        )
        in {
            "HIGH",
            "MEDIUM",
        }
    )

    high_risk_events = (
        risk_breakdown.get(
            "HIGH",
            0,
        )
    )

    critical_incidents = (
        incident_severity.get(
            "CRITICAL",
            0,
        )
    )

    open_incidents = (
        incident_status.get(
            "OPEN",
            0,
        )
    )

    investigating_incidents = (
        incident_status.get(
            "INVESTIGATING",
            0,
        )
    )

    average_event_risk = (
        round(
            sum(
                float(
                    row.get(
                        "risk_score"
                    )
                    or
                    0
                )
                for row
                in security_events
            )
            /
            len(
                security_events
            ),
            2,
        )
        if security_events
        else
        0
    )

    average_identity_score = (
        round(
            sum(
                float(
                    row.get(
                        "security_score"
                    )
                    or
                    0
                )
                for row
                in security_scores
            )
            /
            len(
                security_scores
            ),
            2,
        )
        if security_scores
        else
        0
    )

    recent_incidents = sorted(
        incidents,
        key=lambda row: (
            row.get(
                "last_detected_at"
            )
            or
            ""
        ),
        reverse=True,
    )[:20]

    top_indicators = (
        report_top_indicators(
            threat_intel,
            limit=15,
        )
    )

    top_domains = (
        report_top_indicators(
            threat_intel,
            limit=10,
            indicator_types=[
                "domain"
            ],
        )
    )

    top_urls = (
        report_top_indicators(
            threat_intel,
            limit=10,
            indicator_types=[
                "url"
            ],
        )
    )

    top_ips = (
        report_top_indicators(
            threat_intel,
            limit=10,
            indicator_types=[
                "ip"
            ],
        )
    )

    top_email_indicators = (
        report_top_indicators(
            threat_intel,
            limit=10,
            indicator_types=[
                "email"
            ],
        )
    )

    return {
        "report_type":
            "CyberShield Security Report",

        "generated_at":
            report_end.isoformat(),

        "period": {
            "days":
                days,

            "from":
                report_start.isoformat(),

            "to":
                report_end.isoformat(),
        },

        "executive_summary": {
            "total_scans":
                total_scans,

            "security_events":
                len(
                    security_events
                ),

            "medium_or_high_events":
                high_medium_events,

            "high_risk_events":
                high_risk_events,

            "total_incidents":
                len(
                    incidents
                ),

            "open_incidents":
                open_incidents,

            "investigating_incidents":
                investigating_incidents,

            "critical_incidents":
                critical_incidents,

            "active_threat_indicators":
                sum(
                    1
                    for row
                    in threat_intel
                    if row.get(
                        "status"
                    )
                    ==
                    "ACTIVE"
                ),

            "average_event_risk":
                average_event_risk,

            "identity_profiles":
                len(
                    security_scores
                ),

            "average_identity_security_score":
                average_identity_score,
        },

        "scan_activity": {
            "url":
                len(
                    url_scans
                ),

            "file":
                len(
                    file_scans
                ),

            "login":
                len(
                    login_scans
                ),

            "qr":
                len(
                    qr_scans
                ),

            "email":
                len(
                    email_scans
                ),

            "total":
                total_scans,
        },

        "security_event_breakdown": {
            "by_type":
                event_type_breakdown,

            "by_risk":
                risk_breakdown,
        },

        "incident_breakdown": {
            "by_severity":
                incident_severity,

            "by_status":
                incident_status,
        },

        "threat_intelligence_breakdown": {
            "by_type":
                indicator_type_breakdown,

            "by_severity":
                indicator_severity,
        },

        "security_event_trend":
            build_daily_series(
                security_events,
                "created_at",
                days,
            ),

        "incident_trend":
            build_daily_series(
                incidents,
                "last_detected_at",
                days,
            ),

        "recent_incidents":
            recent_incidents,

        "top_threat_indicators":
            top_indicators,

        "top_domains":
            top_domains,

        "top_urls":
            top_urls,

        "top_ips":
            top_ips,

        "top_email_indicators":
            top_email_indicators,
    }


# ==================================================
# HOME
# ==================================================

@app.get("/")
def home():

    return {
        "status":
            "online",

        "project":
            "CyberShield AI",

        "version":
            "6.6.0",

        "platform":
            (
                "AI-Based Cyber Threat Detection, "
                "Prevention & Awareness Platform"
            ),

        "modules": [
            "Hybrid URL Threat Detection",
            "Advanced File Threat Detection",
            "Suspicious Login Detection",
            "Identity Security Score",
            "Login Monitoring",
            "QR Analyzer",
            "Email Phishing Analyzer",
            "Explainable Threat Results",
            "Prevention Recommendations",
            "Unified Security Event Logging",
            "Automatic Threat Correlation",
            "Incident Timeline Engine",
            "Incident Reporting Engine",
            "Internal Threat Intelligence",
            "URL Reputation Engine",
            "Live Threat Feed",
            "Protected Admin SOC APIs",
        ],
    }


# ==================================================
# URL ANALYZER
# ==================================================

@app.post("/analyze")
def analyze_url(
    data: URLRequest,
    session_id: Optional[str] = Header(
        default=None,
        alias="X-CyberShield-Session",
    ),
):

    result = (
        analyze_url_signals(
            str(
                data.url
            )
        )
    )

    session_id = (
        normalize_session_id(
            session_id
        )
    )

    explanation = (
        build_explainability(
            "url",
            result[
                "risk_level"
            ],
            result[
                "reasons"
            ],
            ml_probability=
                result[
                    "ml_analysis"
                ][
                    "malicious_probability"
                ],
            heuristic_score=
                result[
                    "heuristic_analysis"
                ][
                    "risk_score"
                ],
        )
    )

    prevention_actions = (
        get_prevention_actions(
            "url",
            result[
                "risk_level"
            ],
            result[
                "prediction"
            ],
        )
    )

    database_saved = (
        False
    )

    source_id = (
        None
    )

    try:

        response = (
            supabase
            .table(
                "url_scans"
            )
            .insert({
                "url":
                    result[
                        "url"
                    ],

                "prediction":
                    result[
                        "prediction"
                    ],

                "confidence":
                    result[
                        "confidence"
                    ],

                "malicious_probability":
                    result[
                        "final_risk_score"
                    ],

                "safe_probability":
                    result[
                        "probabilities"
                    ][
                        "safe"
                    ],
            })
            .execute()
        )

        database_saved = (
            True
        )

        source_id = (
            get_inserted_id(
                response
            )
        )

    except Exception as error:

        print(
            "URL Database Error:",
            error,
        )

    security_event = (
        log_security_event(
            event_type=
                "url",

            source_table=
                "url_scans",

            source_id=
                source_id,

            title=
                "URL threat analysis",

            resource=
                result[
                    "url"
                ],

            prediction=
                result[
                    "prediction"
                ],

            risk_level=
                result[
                    "risk_level"
                ],

            risk_score=
                result[
                    "final_risk_score"
                ],

            reasons=
                result[
                    "reasons"
                ],

            prevention_actions=
                prevention_actions,

            metadata={
                "hostname":
                    result[
                        "hostname"
                    ],

                "trusted_domain":
                    result[
                        "trusted_domain"
                    ],

                "decision_source":
                    result[
                        "decision_source"
                    ],

                "ml_malicious_probability":
                    result[
                        "ml_analysis"
                    ][
                        "malicious_probability"
                    ],

                "heuristic_score":
                    result[
                        "heuristic_analysis"
                    ][
                        "risk_score"
                    ],
            },

            session_id=
                session_id,
        )
    )

    incident = (
        correlate_security_event(
            event_id=
                security_event.get(
                    "event_id"
                ),

            event_type=
                "url",

            risk_level=
                result[
                    "risk_level"
                ],

            risk_score=
                result[
                    "final_risk_score"
                ],

            session_id=
                session_id,

            prevention_actions=
                prevention_actions,
        )
    )

    threat_intelligence = (
        record_threat_intelligence(
            event_type=
                "url",

            prediction=
                result[
                    "prediction"
                ],

            risk_level=
                result[
                    "risk_level"
                ],

            risk_score=
                result[
                    "final_risk_score"
                ],

            resource=
                result[
                    "url"
                ],

            hostname=
                result[
                    "hostname"
                ],

            confidence=
                result[
                    "confidence"
                ],

            security_event_id=
                security_event.get(
                    "event_id"
                ),
        )
    )

    return {
        **result,

        "explainability":
            explanation,

        "prevention_actions":
            prevention_actions,

        "security_event":
            security_event,

        "incident":
            incident,

        "threat_intelligence":
            threat_intelligence,

        "session_id":
            session_id,

        "database_saved":
            database_saved,

        "message":
            "URL analyzed using "
            "CyberShield Hybrid Threat Engine",
    }


# ==================================================
# LOGIN ANALYZER
# ==================================================

@app.post("/analyze-login")
def analyze_login(
    data: LoginRequest,
    session_id: Optional[str] = Header(
        default=None,
        alias="X-CyberShield-Session",
    ),
):

    risk_score = 0
    reasons = []

    if data.failed_attempts >= 10:

        risk_score += 45

        reasons.append(
            "Very high number of failed login attempts"
        )

    elif data.failed_attempts >= 5:

        risk_score += 30

        reasons.append(
            "Multiple failed login attempts detected"
        )

    elif data.failed_attempts >= 3:

        risk_score += 15

        reasons.append(
            "Repeated failed login attempts detected"
        )

    elif data.failed_attempts >= 1:

        risk_score += 5

        reasons.append(
            "Recent failed login attempt detected"
        )

    if data.new_device:

        risk_score += 15

        reasons.append(
            "Login from a new or unknown device"
        )

    if data.unusual_location:

        risk_score += 30

        reasons.append(
            "Login from an unusual location"
        )

    if (
        0
        <=
        data.login_hour
        <=
        5
    ):

        risk_score += 10

        reasons.append(
            "Login occurred during an unusual time period"
        )

    risk_score = min(
        risk_score,
        100,
    )

    if risk_score >= 70:

        risk_level = (
            "HIGH"
        )

        prediction = (
            "suspicious"
        )

    elif risk_score >= 40:

        risk_level = (
            "MEDIUM"
        )

        prediction = (
            "suspicious"
        )

    elif risk_score >= 20:

        risk_level = (
            "LOW"
        )

        prediction = (
            "needs_review"
        )

    else:

        risk_level = (
            "LOW"
        )

        prediction = (
            "normal"
        )

    if risk_level == "HIGH":

        recommendation = (
            "Block or challenge this login attempt "
            "and require additional verification."
        )

    elif risk_level == "MEDIUM":

        recommendation = (
            "Request additional authentication "
            "before allowing access."
        )

    elif prediction == "needs_review":

        recommendation = (
            "Login activity should be monitored "
            "for additional suspicious behavior."
        )

    else:

        recommendation = (
            "No strong suspicious login "
            "indicators detected."
        )

    explanation = (
        build_explainability(
            "login",
            risk_level,
            reasons,
        )
    )

    prevention_actions = (
        get_prevention_actions(
            "login",
            risk_level,
            prediction,
        )
    )

    database_saved = (
        False
    )

    source_id = (
        None
    )

    try:

        response = (
            supabase
            .table(
                "login_scans"
            )
            .insert({
                "user_identifier":
                    data.user_identifier,

                "ip_address":
                    data.ip_address,

                "failed_attempts":
                    data.failed_attempts,

                "new_device":
                    data.new_device,

                "unusual_location":
                    data.unusual_location,

                "login_hour":
                    data.login_hour,

                "prediction":
                    prediction,

                "risk_level":
                    risk_level,

                "risk_score":
                    risk_score,

                "reasons":
                    reasons,
            })
            .execute()
        )

        database_saved = (
            True
        )

        source_id = (
            get_inserted_id(
                response
            )
        )

    except Exception as error:

        print(
            "Login Database Error:",
            error,
        )

    session_id = (
        normalize_session_id(
            session_id
        )
    )

    security_event = (
        log_security_event(
            event_type=
                "login",

            source_table=
                "login_scans",

            source_id=
                source_id,

            actor_identifier=
                data.user_identifier,

            title=
                "Login risk analysis",

            resource=
                data.ip_address,

            prediction=
                prediction,

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            reasons=
                reasons,

            prevention_actions=
                prevention_actions,

            metadata={
                "ip_address":
                    data.ip_address,

                "failed_attempts":
                    data.failed_attempts,

                "new_device":
                    data.new_device,

                "unusual_location":
                    data.unusual_location,

                "login_hour":
                    data.login_hour,
            },

            session_id=
                session_id,

            correlation_key=
                data.user_identifier,
        )
    )

    incident = (
        correlate_security_event(
            event_id=
                security_event.get(
                    "event_id"
                ),

            event_type=
                "login",

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            session_id=
                session_id,

            correlation_key=
                data.user_identifier,

            prevention_actions=
                prevention_actions,
        )
    )

    threat_intelligence = (
        record_threat_intelligence(
            event_type=
                "login",

            prediction=
                prediction,

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            ip_address=
                data.ip_address,

            security_event_id=
                security_event.get(
                    "event_id"
                ),
        )
    )

    identity_security = (
        calculate_identity_security_score(
            data.user_identifier
        )
    )

    return {
        "user_identifier":
            data.user_identifier,

        "ip_address":
            data.ip_address,

        "prediction":
            prediction,

        "risk_level":
            risk_level,

        "risk_score":
            risk_score,

        "reasons":
            reasons,

        "recommendation":
            recommendation,

        "explainability":
            explanation,

        "prevention_actions":
            prevention_actions,

        "identity_security":
            identity_security,

        "security_event":
            security_event,

        "incident":
            incident,

        "threat_intelligence":
            threat_intelligence,

        "session_id":
            session_id,

        "database_saved":
            database_saved,

        "message":
            "Login activity analyzed successfully",
    }


# ==================================================
# QR ANALYZER
# ==================================================

@app.post("/scan-qr")
async def scan_qr(
    file: UploadFile = File(...),
    session_id: Optional[str] = Header(
        default=None,
        alias="X-CyberShield-Session",
    ),
):

    MAX_QR_SIZE = (
        10
        *
        1024
        *
        1024
    )

    content = await file.read(
        MAX_QR_SIZE
        +
        1
    )

    if len(
        content
    ) > MAX_QR_SIZE:

        raise HTTPException(
            status_code=413,
            detail=(
                "QR image too large. "
                "Maximum supported size is 10 MB."
            ),
        )

    if not content:

        raise HTTPException(
            status_code=400,
            detail=(
                "Uploaded QR image is empty."
            ),
        )

    image_array = (
        np.frombuffer(
            content,
            dtype=np.uint8,
        )
    )

    image = (
        cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR,
        )
    )

    if image is None:

        raise HTTPException(
            status_code=400,
            detail=(
                "Uploaded file is not a valid image."
            ),
        )

    detector = (
        cv2.QRCodeDetector()
    )

    (
        decoded_content,
        _,
        _,
    ) = (
        detector.detectAndDecode(
            image
        )
    )

    decoded_content = (
        decoded_content
        or
        ""
    ).strip()

    if not decoded_content:

        raise HTTPException(
            status_code=422,
            detail=(
                "No readable QR code was detected. "
                "Try a clearer QR image."
            ),
        )

    extracted_url = (
        extract_url_from_qr_content(
            decoded_content
        )
    )

    decoded_type = (
        "url"
        if extracted_url
        else
        "text"
    )

    session_id = (
        normalize_session_id(
            session_id
        )
    )

    if extracted_url:

        url_analysis = (
            analyze_url_signals(
                extracted_url
            )
        )

        prediction = (
            url_analysis[
                "prediction"
            ]
        )

        risk_level = (
            url_analysis[
                "risk_level"
            ]
        )

        risk_score = (
            url_analysis[
                "final_risk_score"
            ]
        )

        confidence = (
            url_analysis[
                "confidence"
            ]
        )

        hostname = (
            url_analysis[
                "hostname"
            ]
        )

        reasons = [
            "QR code contains a web destination",
            *(
                url_analysis.get(
                    "reasons"
                )
                or
                []
            ),
        ]

        explanation = (
            build_explainability(
                "url",
                risk_level,
                reasons,
                ml_probability=
                    url_analysis[
                        "ml_analysis"
                    ][
                        "malicious_probability"
                    ],
                heuristic_score=
                    url_analysis[
                        "heuristic_analysis"
                    ][
                        "risk_score"
                    ],
            )
        )

        explanation[
            "button_label"
        ] = (
            "Why was this QR code flagged?"
        )

        prevention_actions = (
            get_prevention_actions(
                "qr",
                risk_level,
                prediction,
            )
        )

    else:

        url_analysis = (
            None
        )

        prediction = (
            "text_content"
        )

        risk_level = (
            "LOW"
        )

        risk_score = (
            0
        )

        confidence = (
            None
        )

        hostname = (
            None
        )

        reasons = [
            "QR code contains non-URL text, "
            "so the URL threat engine was not applicable."
        ]

        explanation = {
            "available":
                True,

            "button_label":
                "Why this result?",

            "title":
                "QR content analysis",

            "items": [
                {
                    "title":
                        reasons[0],

                    "category":
                        "qr_content",

                    "severity":
                        "low",
                }
            ],
        }

        prevention_actions = [
            {
                "title":
                    "Review unexpected QR text before "
                    "acting on its instructions",

                "priority":
                    "low",
            }
        ]

    database_saved = (
        False
    )

    source_id = (
        None
    )

    try:

        response = (
            supabase
            .table(
                "qr_scans"
            )
            .insert({
                "file_name":
                    file.filename
                    or
                    "qr-image",

                "decoded_content":
                    decoded_content,

                "decoded_type":
                    decoded_type,

                "extracted_url":
                    extracted_url,

                "prediction":
                    prediction,

                "risk_level":
                    risk_level,

                "risk_score":
                    clamp_score(
                        risk_score
                    ),

                "reasons":
                    reasons,
            })
            .execute()
        )

        database_saved = (
            True
        )

        source_id = (
            get_inserted_id(
                response
            )
        )

    except Exception as error:

        print(
            "QR Database Error:",
            error,
        )

    security_event = (
        log_security_event(
            event_type=
                "qr",

            source_table=
                "qr_scans",

            source_id=
                source_id,

            title=
                "QR code threat analysis",

            resource=
                (
                    extracted_url
                    or
                    decoded_content[
                        :500
                    ]
                ),

            prediction=
                prediction,

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            reasons=
                reasons,

            prevention_actions=
                prevention_actions,

            metadata={
                "file_name":
                    file.filename
                    or
                    "qr-image",

                "decoded_type":
                    decoded_type,

                "extracted_url":
                    extracted_url,

                "hostname":
                    hostname,
            },

            session_id=
                session_id,
        )
    )

    incident = (
        correlate_security_event(
            event_id=
                security_event.get(
                    "event_id"
                ),

            event_type=
                "qr",

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            session_id=
                session_id,

            prevention_actions=
                prevention_actions,
        )
    )

    if extracted_url:

        threat_intelligence = (
            record_threat_intelligence(
                event_type=
                    "qr",

                prediction=
                    prediction,

                risk_level=
                    risk_level,

                risk_score=
                    risk_score,

                resource=
                    extracted_url,

                hostname=
                    hostname,

                confidence=
                    confidence,

                security_event_id=
                    security_event.get(
                        "event_id"
                    ),
            )
        )

    else:

        threat_intelligence = {
            "recorded":
                False,

            "indicators":
                [],

            "reason":
                "Non-URL QR content is not entered "
                "into URL/domain threat intelligence.",
        }

    return {
        "file_name":
            file.filename
            or
            "qr-image",

        "decoded_content":
            decoded_content,

        "decoded_type":
            decoded_type,

        "extracted_url":
            extracted_url,

        "prediction":
            prediction,

        "risk_level":
            risk_level,

        "risk_score":
            clamp_score(
                risk_score
            ),

        "reasons":
            reasons,

        "url_analysis":
            url_analysis,

        "explainability":
            explanation,

        "prevention_actions":
            prevention_actions,

        "security_event":
            security_event,

        "incident":
            incident,

        "threat_intelligence":
            threat_intelligence,

        "session_id":
            session_id,

        "database_saved":
            database_saved,

        "message":
            "QR code analyzed successfully",
    }


# ==================================================
# EMAIL ANALYZER
# ==================================================

@app.post("/analyze-email")
def analyze_email(
    data: EmailRequest,
    session_id: Optional[str] = Header(
        default=None,
        alias="X-CyberShield-Session",
    ),
):

    if not any([
        data.sender_email.strip(),
        (
            data.reply_to_email
            or
            ""
        ).strip(),
        data.subject.strip(),
        data.body.strip(),
    ]):

        raise HTTPException(
            status_code=400,
            detail=(
                "Provide email sender, "
                "subject or message content."
            ),
        )

    result = (
        analyze_email_signals(
            sender_email=
                data.sender_email,

            reply_to_email=
                data.reply_to_email,

            subject=
                data.subject,

            body=
                data.body,
        )
    )

    session_id = (
        normalize_session_id(
            session_id
        )
    )

    explanation = (
        build_explainability(
            "email",
            result[
                "risk_level"
            ],
            result[
                "reasons"
            ],
        )
    )

    prevention_actions = (
        get_prevention_actions(
            "email",
            result[
                "risk_level"
            ],
            result[
                "prediction"
            ],
        )
    )

    body_preview = (
        re.sub(
            r"\s+",
            " ",
            data.body
            or
            "",
        )
        .strip()
        [:1200]
    )

    database_saved = (
        False
    )

    source_id = (
        None
    )

    try:

        response = (
            supabase
            .table(
                "email_scans"
            )
            .insert({
                "sender_email":
                    result[
                        "sender_email"
                    ]
                    or
                    None,

                "reply_to_email":
                    result[
                        "reply_to_email"
                    ],

                "subject":
                    result[
                        "subject"
                    ],

                "body_preview":
                    body_preview,

                "extracted_urls":
                    result[
                        "extracted_urls"
                    ],

                "suspicious_keywords":
                    result[
                        "suspicious_keywords"
                    ],

                "reasons":
                    result[
                        "reasons"
                    ],

                "prediction":
                    result[
                        "prediction"
                    ],

                "risk_level":
                    result[
                        "risk_level"
                    ],

                "risk_score":
                    result[
                        "risk_score"
                    ],
            })
            .execute()
        )

        database_saved = (
            True
        )

        source_id = (
            get_inserted_id(
                response
            )
        )

    except Exception as error:

        print(
            "Email Database Error:",
            error,
        )

    security_event = (
        log_security_event(
            event_type=
                "email",

            source_table=
                "email_scans",

            source_id=
                source_id,

            actor_identifier=
                result[
                    "sender_email"
                ]
                or
                None,

            title=
                "Email phishing analysis",

            resource=
                (
                    result[
                        "subject"
                    ][:500]
                    or
                    result[
                        "sender_email"
                    ]
                    or
                    "Email message"
                ),

            prediction=
                result[
                    "prediction"
                ],

            risk_level=
                result[
                    "risk_level"
                ],

            risk_score=
                result[
                    "risk_score"
                ],

            reasons=
                result[
                    "reasons"
                ],

            prevention_actions=
                prevention_actions,

            metadata={
                "sender_email":
                    result[
                        "sender_email"
                    ],

                "reply_to_email":
                    result[
                        "reply_to_email"
                    ],

                "extracted_urls":
                    result[
                        "extracted_urls"
                    ],

                "suspicious_keywords":
                    result[
                        "suspicious_keywords"
                    ],

                "url_analyses":
                    result[
                        "url_analyses"
                    ],
            },

            session_id=
                session_id,

            correlation_key=
                (
                    result[
                        "sender_email"
                    ]
                    or
                    None
                ),
        )
    )

    incident = (
        correlate_security_event(
            event_id=
                security_event.get(
                    "event_id"
                ),

            event_type=
                "email",

            risk_level=
                result[
                    "risk_level"
                ],

            risk_score=
                result[
                    "risk_score"
                ],

            session_id=
                session_id,

            correlation_key=
                (
                    result[
                        "sender_email"
                    ]
                    or
                    None
                ),

            prevention_actions=
                prevention_actions,
        )
    )

    threat_intelligence = (
        record_email_threat_intelligence(
            sender_email=
                result[
                    "sender_email"
                ],

            email_result=
                result,

            security_event_id=
                security_event.get(
                    "event_id"
                ),
        )
    )

    highest_embedded_url_risk = (
        0
    )

    if result[
        "url_analyses"
    ]:

        highest_embedded_url_risk = max(
            float(
                item.get(
                    "final_risk_score"
                )
                or
                0
            )
            for item
            in result[
                "url_analyses"
            ]
        )

    return {
        "sender_email":
            result[
                "sender_email"
            ],

        "reply_to_email":
            result[
                "reply_to_email"
            ],

        "subject":
            result[
                "subject"
            ],

        "prediction":
            result[
                "prediction"
            ],

        "risk_level":
            result[
                "risk_level"
            ],

        "risk_score":
            result[
                "risk_score"
            ],

        "reasons":
            result[
                "reasons"
            ],

        "suspicious_keywords":
            result[
                "suspicious_keywords"
            ],

        "extracted_urls":
            result[
                "extracted_urls"
            ],

        "highest_embedded_url_risk":
            highest_embedded_url_risk,

        "url_analyses":
            result[
                "url_analyses"
            ],

        "detection_method":
            (
                "Email Security Rules + "
                "CyberShield Hybrid URL Analysis"
            ),

        "explainability":
            explanation,

        "prevention_actions":
            prevention_actions,

        "security_event":
            security_event,

        "incident":
            incident,

        "threat_intelligence":
            threat_intelligence,

        "session_id":
            session_id,

        "database_saved":
            database_saved,

        "message":
            "Email phishing analysis completed",
    }


# ==================================================
# FILE ANALYZER
# ==================================================

@app.post("/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    session_id: Optional[str] = Header(
        default=None,
        alias="X-CyberShield-Session",
    ),
):

    MAX_FILE_SIZE = (
        25
        *
        1024
        *
        1024
    )

    content = await file.read(
        MAX_FILE_SIZE
        +
        1
    )

    file_size = (
        len(
            content
        )
    )

    if file_size > MAX_FILE_SIZE:

        raise HTTPException(
            status_code=413,
            detail=(
                "File too large. "
                "Maximum supported size is 25 MB."
            ),
        )

    file_name = (
        file.filename
        or
        "unknown"
    )

    lowercase_name = (
        file_name.lower()
    )

    file_extension = (
        os.path.splitext(
            lowercase_name
        )[1]
    )

    sha256_hash = (
        hashlib.sha256(
            content
        ).hexdigest()
    )

    (
        detected_mime,
        file_description,
    ) = (
        get_file_type_information(
            content
        )
    )

    file_signature = (
        detect_file_signature(
            content
        )
    )

    uploaded_content_type = (
        file.content_type
        or
        "unknown"
    )

    entropy = (
        calculate_entropy(
            content
        )
    )

    risk_score = 0
    reasons = []
    indicators = []
    archive_files = []

    dangerous_extensions = [
        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".msi",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".dll",
        ".com",
    ]

    executable_signatures = [
        "Windows PE executable",
        "Linux ELF executable",
        "Mach-O executable",
    ]

    normal_document_extensions = [
        ".txt",
        ".pdf",
        ".jpg",
        ".jpeg",
        ".png",
        ".doc",
        ".docx",
        ".xlsx",
        ".pptx",
    ]

    if (
        file_extension
        in
        dangerous_extensions
    ):

        risk_score += 35

        reasons.append(
            "Potentially dangerous "
            f"file extension: {file_extension}"
        )

    if (
        len(
            lowercase_name.split(
                "."
            )
        )
        >=
        3
        and
        file_extension
        in
        dangerous_extensions
    ):

        risk_score += 20

        reasons.append(
            "Possible double-extension disguise detected"
        )

    if (
        file_signature
        in
        executable_signatures
    ):

        risk_score += 30

        reasons.append(
            "Executable file signature detected: "
            +
            file_signature
        )

    if (
        file_extension
        in
        normal_document_extensions
        and
        file_signature
        in
        executable_signatures
    ):

        risk_score += 40

        reasons.append(
            "File extension hides executable content"
        )

    dangerous_mime_keywords = [
        "executable",
        "x-dosexec",
        "x-msdownload",
        "sharedlib",
    ]

    if any(
        keyword
        in
        detected_mime.lower()
        for keyword
        in
        dangerous_mime_keywords
    ):

        risk_score += 25

        reasons.append(
            "Executable content type detected"
        )

    text_indicators = (
        scan_text_patterns(
            content
        )
    )

    if text_indicators:

        indicators.extend(
            text_indicators
        )

        risk_score += min(
            len(
                text_indicators
            )
            *
            8,
            32,
        )

        reasons.append(
            "Suspicious script or command patterns detected"
        )

    if (
        file_extension
        ==
        ".pdf"
        or
        file_signature
        ==
        "PDF document"
    ):

        pdf_indicators = (
            scan_pdf(
                content
            )
        )

        if pdf_indicators:

            indicators.extend(
                pdf_indicators
            )

            risk_score += min(
                len(
                    pdf_indicators
                )
                *
                10,
                30,
            )

            reasons.append(
                "Potentially active PDF content detected"
            )

    zip_based_extensions = [
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
        ".jar",
    ]

    if (
        file_extension
        in
        zip_based_extensions
        or
        file_signature
        ==
        "ZIP archive"
    ):

        (
            zip_indicators,
            archive_files,
        ) = (
            scan_zip(
                content
            )
        )

        indicators.extend(
            zip_indicators
        )

        if archive_files:

            risk_score += 25

            reasons.append(
                "Suspicious files detected inside archive"
            )

    compressed_extensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
    ]

    if (
        entropy >= 7.6
        and
        file_size > 2048
        and
        file_extension
        not in
        compressed_extensions
    ):

        risk_score += 15

        reasons.append(
            "Very high entropy detected; "
            "file may be packed, encrypted "
            "or obfuscated"
        )

    elif (
        entropy >= 7.2
        and
        file_size > 2048
        and
        file_extension
        not in
        compressed_extensions
    ):

        risk_score += 5

    risk_score = min(
        risk_score,
        100,
    )

    if risk_score >= 70:

        risk_level = (
            "HIGH"
        )

        prediction = (
            "suspicious"
        )

    elif risk_score >= 40:

        risk_level = (
            "MEDIUM"
        )

        prediction = (
            "suspicious"
        )

    elif risk_score >= 20:

        risk_level = (
            "LOW"
        )

        prediction = (
            "needs_review"
        )

    else:

        risk_level = (
            "LOW"
        )

        prediction = (
            "safe"
        )

    explanation = (
        build_explainability(
            "file",
            risk_level,
            reasons,
            indicators=
                indicators,
        )
    )

    prevention_actions = (
        get_prevention_actions(
            "file",
            risk_level,
            prediction,
        )
    )

    database_saved = (
        False
    )

    source_id = (
        None
    )

    try:

        response = (
            supabase
            .table(
                "file_scans"
            )
            .insert({
                "file_name":
                    file_name,

                "file_size_bytes":
                    file_size,

                "file_extension":
                    file_extension,

                "detected_content_type":
                    detected_mime,

                "sha256":
                    sha256_hash,

                "entropy":
                    entropy,

                "prediction":
                    prediction,

                "risk_level":
                    risk_level,

                "risk_score":
                    risk_score,
            })
            .execute()
        )

        database_saved = (
            True
        )

        source_id = (
            get_inserted_id(
                response
            )
        )

    except Exception as error:

        print(
            "File Database Error:",
            error,
        )

    session_id = (
        normalize_session_id(
            session_id
        )
    )

    security_event = (
        log_security_event(
            event_type=
                "file",

            source_table=
                "file_scans",

            source_id=
                source_id,

            title=
                "File threat analysis",

            resource=
                file_name,

            prediction=
                prediction,

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            reasons=
                reasons,

            prevention_actions=
                prevention_actions,

            metadata={
                "file_extension":
                    file_extension,

                "detected_content_type":
                    detected_mime,

                "file_signature":
                    file_signature,

                "sha256":
                    sha256_hash,

                "entropy":
                    entropy,

                "indicators":
                    indicators,

                "suspicious_archive_files":
                    archive_files,
            },

            session_id=
                session_id,
        )
    )

    incident = (
        correlate_security_event(
            event_id=
                security_event.get(
                    "event_id"
                ),

            event_type=
                "file",

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            session_id=
                session_id,

            prevention_actions=
                prevention_actions,
        )
    )

    threat_intelligence = (
        record_threat_intelligence(
            event_type=
                "file",

            prediction=
                prediction,

            risk_level=
                risk_level,

            risk_score=
                risk_score,

            sha256=
                sha256_hash,

            security_event_id=
                security_event.get(
                    "event_id"
                ),
        )
    )

    return {
        "file_name":
            file_name,

        "file_size_bytes":
            file_size,

        "file_size_kb":
            round(
                file_size
                /
                1024,
                2,
            ),

        "file_extension":
            file_extension,

        "uploaded_content_type":
            uploaded_content_type,

        "detected_content_type":
            detected_mime,

        "file_description":
            file_description,

        "file_signature":
            file_signature,

        "sha256":
            sha256_hash,

        "entropy":
            entropy,

        "prediction":
            prediction,

        "risk_level":
            risk_level,

        "risk_score":
            risk_score,

        "reasons":
            reasons,

        "indicators":
            indicators,

        "suspicious_archive_files":
            archive_files,

        "explainability":
            explanation,

        "prevention_actions":
            prevention_actions,

        "security_event":
            security_event,

        "incident":
            incident,

        "threat_intelligence":
            threat_intelligence,

        "session_id":
            session_id,

        "database_saved":
            database_saved,

        "message":
            "Advanced static file analysis completed",
    }


# ==================================================
# THREAT INTELLIGENCE APIs
# ==================================================

@app.get(
    "/threat-intelligence/feed"
)
def threat_intelligence_feed(
    limit: int = 20
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            100,
        ),
    )

    try:

        records = (
            supabase
            .table(
                "threat_intelligence"
            )
            .select("*")
            .eq(
                "status",
                "ACTIVE",
            )
            .order(
                "last_seen_at",
                desc=True,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        return {
            "feed_type":
                "internal_live_threat_feed",

            "source":
                "CyberShield Internal",

            "count":
                len(
                    records
                ),

            "items":
                records,
        }

    except Exception as error:

        print(
            "Threat Feed Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load threat feed"
            ),
        )


@app.get(
    "/threat-intelligence/recent"
)
def recent_threats(
    limit: int = 20
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            100,
        ),
    )

    try:

        records = (
            supabase
            .table(
                "security_events"
            )
            .select("*")
            .in_(
                "risk_level",
                [
                    "MEDIUM",
                    "HIGH",
                ],
            )
            .order(
                "created_at",
                desc=True,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        return {
            "source":
                "CyberShield Security Events",

            "count":
                len(
                    records
                ),

            "threats":
                records,
        }

    except Exception as error:

        print(
            "Recent Threats Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load recent threats"
            ),
        )


@app.post(
    "/threat-intelligence/url-reputation"
)
def url_reputation(
    data: URLRequest
):

    return (
        query_url_reputation(
            str(
                data.url
            )
        )
    )


# ==================================================
# HISTORY + BASIC STATS
# ==================================================

@app.get("/history")
def get_history():

    try:

        records = (
            supabase
            .table(
                "url_scans"
            )
            .select("*")
            .order(
                "created_at",
                desc=True,
            )
            .limit(100)
            .execute()
            .data
            or []
        )

        return {
            "total_records":
                len(
                    records
                ),

            "history":
                records,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(
                error
            ),
        )


@app.get("/stats")
def get_stats():

    try:

        records = (
            supabase
            .table(
                "url_scans"
            )
            .select("*")
            .execute()
            .data
            or []
        )

        return {
            "total_scans":
                len(
                    records
                ),

            "safe_count":
                sum(
                    1
                    for row
                    in records
                    if row.get(
                        "prediction"
                    )
                    ==
                    "safe"
                ),

            "malicious_count":
                sum(
                    1
                    for row
                    in records
                    if row.get(
                        "prediction"
                    )
                    ==
                    "malicious"
                ),

            "needs_review":
                sum(
                    1
                    for row
                    in records
                    if row.get(
                        "prediction"
                    )
                    ==
                    "needs_review"
                ),
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(
                error
            ),
        )


# ==================================================
# ADMIN AUTH
# ==================================================

def create_admin_token():

    now = (
        utc_now()
    )

    return jwt.encode(
        {
            "sub":
                ADMIN_USERNAME,

            "role":
                "admin",

            "iat":
                now,

            "exp":
                now
                +
                timedelta(
                    hours=2
                ),
        },
        ADMIN_TOKEN_SECRET,
        algorithm=
            "HS256",
    )


def verify_admin_token(
    credentials: Optional[
        HTTPAuthorizationCredentials
    ] = Depends(
        admin_security
    )
):

    if credentials is None:

        raise HTTPException(
            status_code=401,
            detail=(
                "Admin authentication required"
            ),
        )

    try:

        payload = jwt.decode(
            credentials.credentials,
            ADMIN_TOKEN_SECRET,
            algorithms=[
                "HS256"
            ],
        )

        if (
            payload.get(
                "sub"
            )
            !=
            ADMIN_USERNAME
            or
            payload.get(
                "role"
            )
            !=
            "admin"
        ):

            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid admin token"
                ),
            )

        return payload.get(
            "sub"
        )

    except jwt.ExpiredSignatureError:

        raise HTTPException(
            status_code=401,
            detail=(
                "Admin session expired"
            ),
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid admin token"
            ),
        )


@app.post("/admin/login")
def admin_login(
    data: AdminLoginRequest
):

    username_valid = (
        secrets.compare_digest(
            data.username,
            ADMIN_USERNAME,
        )
    )

    password_valid = (
        secrets.compare_digest(
            data.password,
            ADMIN_PASSWORD,
        )
    )

    if not (
        username_valid
        and
        password_valid
    ):

        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid username or password"
            ),
        )

    return {
        "access_token":
            create_admin_token(),

        "token_type":
            "bearer",

        "expires_in_seconds":
            7200,

        "message":
            "Admin login successful",
    }


# ==================================================
# ADMIN LOGIN MONITORING
# ==================================================

@app.get(
    "/admin/login-monitoring"
)
def admin_login_monitoring(
    actor_identifier: Optional[str] = None,
    limit: int = 100,
    admin: str = Depends(
        verify_admin_token
    ),
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            500,
        ),
    )

    try:

        query = (
            supabase
            .table(
                "login_scans"
            )
            .select("*")
        )

        if actor_identifier:

            query = (
                query.eq(
                    "user_identifier",
                    actor_identifier,
                )
            )

        records = (
            query
            .order(
                "created_at",
                desc=True,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        return {
            "admin":
                admin,

            "actor_identifier":
                actor_identifier,

            "count":
                len(
                    records
                ),

            "high_risk":
                sum(
                    1
                    for row
                    in records
                    if row.get(
                        "risk_level"
                    )
                    ==
                    "HIGH"
                ),

            "medium_risk":
                sum(
                    1
                    for row
                    in records
                    if row.get(
                        "risk_level"
                    )
                    ==
                    "MEDIUM"
                ),

            "new_device_events":
                sum(
                    1
                    for row
                    in records
                    if bool(
                        row.get(
                            "new_device"
                        )
                    )
                ),

            "unusual_location_events":
                sum(
                    1
                    for row
                    in records
                    if bool(
                        row.get(
                            "unusual_location"
                        )
                    )
                ),

            "login_events":
                records,
        }

    except Exception as error:

        print(
            "Login Monitoring Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load login monitoring data"
            ),
        )


# ==================================================
# ADMIN IDENTITY SECURITY
# ==================================================

@app.get(
    "/admin/identity-security"
)
def admin_identity_security(
    limit: int = 100,
    admin: str = Depends(
        verify_admin_token
    ),
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            500,
        ),
    )

    try:

        records = (
            supabase
            .table(
                "security_scores"
            )
            .select("*")
            .order(
                "security_score",
                desc=False,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        average_score = (
            round(
                sum(
                    float(
                        row.get(
                            "security_score"
                        )
                        or
                        0
                    )
                    for row
                    in records
                )
                /
                len(
                    records
                ),
                2,
            )
            if records
            else
            0
        )

        return {
            "admin":
                admin,

            "count":
                len(
                    records
                ),

            "average_security_score":
                average_score,

            "score_method":
                (
                    "Observed login behaviour "
                    "over the most recent 30 days"
                ),

            "profiles":
                records,
        }

    except Exception as error:

        print(
            "Identity Security Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load identity security profiles"
            ),
        )


@app.get(
    "/admin/identity-security/{actor_identifier}"
)
def admin_identity_security_detail(
    actor_identifier: str,
    admin: str = Depends(
        verify_admin_token
    ),
):

    try:

        profile_rows = (
            supabase
            .table(
                "security_scores"
            )
            .select("*")
            .eq(
                "actor_identifier",
                actor_identifier,
            )
            .limit(1)
            .execute()
            .data
            or []
        )

        if not profile_rows:

            recalculated = (
                calculate_identity_security_score(
                    actor_identifier
                )
            )

            if not recalculated.get(
                "calculated"
            ):

                raise HTTPException(
                    status_code=404,
                    detail=(
                        "Identity security profile not found"
                    ),
                )

            profile = (
                recalculated[
                    "score"
                ]
            )

        else:

            profile = (
                profile_rows[0]
            )

        recent_logins = (
            supabase
            .table(
                "login_scans"
            )
            .select("*")
            .eq(
                "user_identifier",
                actor_identifier,
            )
            .order(
                "created_at",
                desc=True,
            )
            .limit(50)
            .execute()
            .data
            or []
        )

        security_events = (
            supabase
            .table(
                "security_events"
            )
            .select("*")
            .eq(
                "actor_identifier",
                actor_identifier,
            )
            .order(
                "created_at",
                desc=True,
            )
            .limit(50)
            .execute()
            .data
            or []
        )

        return {
            "admin":
                admin,

            "profile":
                profile,

            "recent_logins":
                recent_logins,

            "security_events":
                security_events,

            "score_window_days":
                IDENTITY_SCORE_WINDOW_DAYS,
        }

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Identity Security Detail Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load identity security details"
            ),
        )


@app.post(
    "/admin/identity-security/{actor_identifier}/recalculate"
)
def admin_recalculate_identity_score(
    actor_identifier: str,
    admin: str = Depends(
        verify_admin_token
    ),
):

    result = (
        calculate_identity_security_score(
            actor_identifier
        )
    )

    if not result.get(
        "calculated"
    ):

        raise HTTPException(
            status_code=500,
            detail=result.get(
                "reason",
                "Unable to calculate score",
            ),
        )

    return {
        "admin":
            admin,

        "message":
            "Identity security score recalculated",

        **result,
    }


# ==================================================
# ADMIN REPORTS - V6.6
# ==================================================

@app.get(
    "/admin/reports/summary"
)
def admin_report_summary(
    days: int = 30,
    admin: str = Depends(
        verify_admin_token
    ),
):

    report = (
        build_security_report(
            days
        )
    )

    return {
        "admin":
            admin,

        **report,
    }


@app.get(
    "/admin/reports/incidents"
)
def admin_incident_report(
    days: int = 30,
    admin: str = Depends(
        verify_admin_token
    ),
):

    days = (
        validate_report_days(
            days
        )
    )

    report_end = (
        utc_now()
    )

    report_start = (
        report_end
        -
        timedelta(
            days=
                days
        )
    )

    all_incidents = (
        safe_table_rows(
            "incidents"
        )
    )

    incidents = (
        filter_rows_by_time(
            all_incidents,
            "last_detected_at",
            report_start,
        )
    )

    incidents = sorted(
        incidents,
        key=lambda row: (
            row.get(
                "last_detected_at"
            )
            or
            ""
        ),
        reverse=True,
    )

    severity_breakdown = (
        count_field_values(
            incidents,
            "severity",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ],
        )
    )

    status_breakdown = (
        count_field_values(
            incidents,
            "status",
            [
                "OPEN",
                "INVESTIGATING",
                "RESOLVED",
            ],
        )
    )

    average_risk = (
        round(
            sum(
                float(
                    row.get(
                        "risk_score"
                    )
                    or
                    0
                )
                for row
                in incidents
            )
            /
            len(
                incidents
            ),
            2,
        )
        if incidents
        else
        0
    )

    return {
        "admin":
            admin,

        "report_type":
            "Incident Report",

        "generated_at":
            report_end.isoformat(),

        "period": {
            "days":
                days,

            "from":
                report_start.isoformat(),

            "to":
                report_end.isoformat(),
        },

        "summary": {
            "total_incidents":
                len(
                    incidents
                ),

            "average_incident_risk":
                average_risk,

            "open":
                status_breakdown.get(
                    "OPEN",
                    0,
                ),

            "investigating":
                status_breakdown.get(
                    "INVESTIGATING",
                    0,
                ),

            "resolved":
                status_breakdown.get(
                    "RESOLVED",
                    0,
                ),

            "critical":
                severity_breakdown.get(
                    "CRITICAL",
                    0,
                ),
        },

        "severity_breakdown":
            severity_breakdown,

        "status_breakdown":
            status_breakdown,

        "trend":
            build_daily_series(
                incidents,
                "last_detected_at",
                days,
            ),

        "incidents":
            incidents,
    }


@app.get(
    "/admin/reports/threats"
)
def admin_threat_report(
    days: int = 30,
    admin: str = Depends(
        verify_admin_token
    ),
):

    days = (
        validate_report_days(
            days
        )
    )

    report_end = (
        utc_now()
    )

    report_start = (
        report_end
        -
        timedelta(
            days=
                days
        )
    )

    all_indicators = (
        safe_table_rows(
            "threat_intelligence"
        )
    )

    indicators = (
        filter_rows_by_time(
            all_indicators,
            "last_seen_at",
            report_start,
        )
    )

    type_breakdown = (
        count_field_values(
            indicators,
            "indicator_type",
            [
                "url",
                "domain",
                "ip",
                "file_hash",
                "email",
            ],
        )
    )

    severity_breakdown = (
        count_field_values(
            indicators,
            "severity",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ],
        )
    )

    total_sightings = sum(
        int(
            row.get(
                "sighting_count"
            )
            or
            0
        )
        for row
        in indicators
    )

    return {
        "admin":
            admin,

        "report_type":
            "Threat Intelligence Report",

        "generated_at":
            report_end.isoformat(),

        "period": {
            "days":
                days,

            "from":
                report_start.isoformat(),

            "to":
                report_end.isoformat(),
        },

        "summary": {
            "unique_indicators":
                len(
                    indicators
                ),

            "total_sightings":
                total_sightings,

            "active_indicators":
                sum(
                    1
                    for row
                    in indicators
                    if row.get(
                        "status"
                    )
                    ==
                    "ACTIVE"
                ),

            "high_severity":
                severity_breakdown.get(
                    "HIGH",
                    0,
                ),

            "critical_severity":
                severity_breakdown.get(
                    "CRITICAL",
                    0,
                ),
        },

        "type_breakdown":
            type_breakdown,

        "severity_breakdown":
            severity_breakdown,

        "top_indicators":
            report_top_indicators(
                indicators,
                limit=20,
            ),

        "top_domains":
            report_top_indicators(
                indicators,
                limit=10,
                indicator_types=[
                    "domain"
                ],
            ),

        "top_urls":
            report_top_indicators(
                indicators,
                limit=10,
                indicator_types=[
                    "url"
                ],
            ),

        "top_ips":
            report_top_indicators(
                indicators,
                limit=10,
                indicator_types=[
                    "ip"
                ],
            ),

        "top_email_indicators":
            report_top_indicators(
                indicators,
                limit=10,
                indicator_types=[
                    "email"
                ],
            ),

        "indicators":
            sorted(
                indicators,
                key=lambda row: (
                    row.get(
                        "last_seen_at"
                    )
                    or
                    ""
                ),
                reverse=True,
            ),
    }


# ==================================================
# ADMIN STATS
# ==================================================

@app.get("/admin/stats")
def admin_stats(
    admin: str = Depends(
        verify_admin_token
    ),
):

    try:

        url_records = (
            safe_table_rows(
                "url_scans"
            )
        )

        file_records = (
            safe_table_rows(
                "file_scans"
            )
        )

        login_records = (
            safe_table_rows(
                "login_scans"
            )
        )

        qr_records = (
            safe_table_rows(
                "qr_scans"
            )
        )

        email_records = (
            safe_table_rows(
                "email_scans"
            )
        )

        security_events = (
            safe_table_rows(
                "security_events"
            )
        )

        incidents = (
            safe_table_rows(
                "incidents"
            )
        )

        threat_intel = (
            safe_table_rows(
                "threat_intelligence"
            )
        )

        security_scores = (
            safe_table_rows(
                "security_scores"
            )
        )

        safe_urls = sum(
            1
            for row
            in url_records
            if row.get(
                "prediction"
            )
            ==
            "safe"
        )

        malicious_urls = sum(
            1
            for row
            in url_records
            if row.get(
                "prediction"
            )
            ==
            "malicious"
        )

        review_urls = sum(
            1
            for row
            in url_records
            if row.get(
                "prediction"
            )
            ==
            "needs_review"
        )

        safe_files = sum(
            1
            for row
            in file_records
            if row.get(
                "prediction"
            )
            ==
            "safe"
        )

        suspicious_files = sum(
            1
            for row
            in file_records
            if row.get(
                "prediction"
            )
            ==
            "suspicious"
        )

        review_files = sum(
            1
            for row
            in file_records
            if row.get(
                "prediction"
            )
            ==
            "needs_review"
        )

        normal_logins = sum(
            1
            for row
            in login_records
            if row.get(
                "prediction"
            )
            ==
            "normal"
        )

        suspicious_logins = sum(
            1
            for row
            in login_records
            if row.get(
                "prediction"
            )
            ==
            "suspicious"
        )

        review_logins = sum(
            1
            for row
            in login_records
            if row.get(
                "prediction"
            )
            ==
            "needs_review"
        )

        safe_qr = sum(
            1
            for row
            in qr_records
            if row.get(
                "prediction"
            )
            in
            {
                "safe",
                "text_content",
            }
        )

        malicious_qr = sum(
            1
            for row
            in qr_records
            if row.get(
                "prediction"
            )
            ==
            "malicious"
        )

        review_qr = sum(
            1
            for row
            in qr_records
            if row.get(
                "prediction"
            )
            ==
            "needs_review"
        )

        safe_email = sum(
            1
            for row
            in email_records
            if row.get(
                "prediction"
            )
            ==
            "safe"
        )

        suspicious_email = sum(
            1
            for row
            in email_records
            if row.get(
                "prediction"
            )
            ==
            "suspicious"
        )

        review_email = sum(
            1
            for row
            in email_records
            if row.get(
                "prediction"
            )
            ==
            "needs_review"
        )

        total_scans = (
            len(
                url_records
            )
            +
            len(
                file_records
            )
            +
            len(
                login_records
            )
            +
            len(
                qr_records
            )
            +
            len(
                email_records
            )
        )

        confirmed_threats = (
            malicious_urls
            +
            suspicious_files
            +
            suspicious_logins
            +
            malicious_qr
            +
            suspicious_email
        )

        needs_review = (
            review_urls
            +
            review_files
            +
            review_logins
            +
            review_qr
            +
            review_email
        )

        safe_or_normal = (
            safe_urls
            +
            safe_files
            +
            normal_logins
            +
            safe_qr
            +
            safe_email
        )

        threat_percentage = (
            round(
                confirmed_threats
                /
                total_scans
                *
                100,
                2,
            )
            if total_scans
            else
            0
        )

        average_identity_score = (
            round(
                sum(
                    float(
                        row.get(
                            "security_score"
                        )
                        or
                        0
                    )
                    for row
                    in security_scores
                )
                /
                len(
                    security_scores
                ),
                2,
            )
            if security_scores
            else
            0
        )

        return {
            "admin":
                admin,

            "overall": {
                "total_scans":
                    total_scans,

                "confirmed_threats":
                    confirmed_threats,

                "needs_review":
                    needs_review,

                "safe_or_normal":
                    safe_or_normal,

                "threat_percentage":
                    threat_percentage,
            },

            "url_scanner": {
                "total":
                    len(
                        url_records
                    ),

                "safe":
                    safe_urls,

                "malicious":
                    malicious_urls,

                "needs_review":
                    review_urls,
            },

            "file_scanner": {
                "total":
                    len(
                        file_records
                    ),

                "safe":
                    safe_files,

                "suspicious":
                    suspicious_files,

                "needs_review":
                    review_files,
            },

            "login_scanner": {
                "total":
                    len(
                        login_records
                    ),

                "normal":
                    normal_logins,

                "suspicious":
                    suspicious_logins,

                "needs_review":
                    review_logins,
            },

            "qr_scanner": {
                "total":
                    len(
                        qr_records
                    ),

                "safe_or_text":
                    safe_qr,

                "malicious":
                    malicious_qr,

                "needs_review":
                    review_qr,
            },

            "email_scanner": {
                "total":
                    len(
                        email_records
                    ),

                "safe":
                    safe_email,

                "suspicious":
                    suspicious_email,

                "needs_review":
                    review_email,
            },

            "identity_security": {
                "profiles":
                    len(
                        security_scores
                    ),

                "average_security_score":
                    average_identity_score,

                "excellent":
                    sum(
                        1
                        for row
                        in security_scores
                        if row.get(
                            "score_level"
                        )
                        ==
                        "EXCELLENT"
                    ),

                "good":
                    sum(
                        1
                        for row
                        in security_scores
                        if row.get(
                            "score_level"
                        )
                        ==
                        "GOOD"
                    ),

                "fair":
                    sum(
                        1
                        for row
                        in security_scores
                        if row.get(
                            "score_level"
                        )
                        ==
                        "FAIR"
                    ),

                "poor":
                    sum(
                        1
                        for row
                        in security_scores
                        if row.get(
                            "score_level"
                        )
                        ==
                        "POOR"
                    ),

                "critical":
                    sum(
                        1
                        for row
                        in security_scores
                        if row.get(
                            "score_level"
                        )
                        ==
                        "CRITICAL"
                    ),
            },

            "security_events": {
                "total":
                    len(
                        security_events
                    ),

                "high":
                    sum(
                        1
                        for row
                        in security_events
                        if row.get(
                            "risk_level"
                        )
                        ==
                        "HIGH"
                    ),

                "medium":
                    sum(
                        1
                        for row
                        in security_events
                        if row.get(
                            "risk_level"
                        )
                        ==
                        "MEDIUM"
                    ),

                "low":
                    sum(
                        1
                        for row
                        in security_events
                        if row.get(
                            "risk_level"
                        )
                        ==
                        "LOW"
                    ),
            },

            "incidents": {
                "total":
                    len(
                        incidents
                    ),

                "open":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "status"
                        )
                        ==
                        "OPEN"
                    ),

                "investigating":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "status"
                        )
                        ==
                        "INVESTIGATING"
                    ),

                "resolved":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "status"
                        )
                        ==
                        "RESOLVED"
                    ),

                "critical":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "severity"
                        )
                        ==
                        "CRITICAL"
                    ),

                "high":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "severity"
                        )
                        ==
                        "HIGH"
                    ),

                "medium":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "severity"
                        )
                        ==
                        "MEDIUM"
                    ),

                "low":
                    sum(
                        1
                        for row
                        in incidents
                        if row.get(
                            "severity"
                        )
                        ==
                        "LOW"
                    ),
            },

            "threat_intelligence": {
                "total_indicators":
                    len(
                        threat_intel
                    ),

                "active":
                    sum(
                        1
                        for row
                        in threat_intel
                        if row.get(
                            "status"
                        )
                        ==
                        "ACTIVE"
                    ),

                "urls":
                    sum(
                        1
                        for row
                        in threat_intel
                        if row.get(
                            "indicator_type"
                        )
                        ==
                        "url"
                    ),

                "domains":
                    sum(
                        1
                        for row
                        in threat_intel
                        if row.get(
                            "indicator_type"
                        )
                        ==
                        "domain"
                    ),

                "file_hashes":
                    sum(
                        1
                        for row
                        in threat_intel
                        if row.get(
                            "indicator_type"
                        )
                        ==
                        "file_hash"
                    ),

                "ips":
                    sum(
                        1
                        for row
                        in threat_intel
                        if row.get(
                            "indicator_type"
                        )
                        ==
                        "ip"
                    ),

                "emails":
                    sum(
                        1
                        for row
                        in threat_intel
                        if row.get(
                            "indicator_type"
                        )
                        ==
                        "email"
                    ),
            },

            "reports": {
                "summary_endpoint":
                    "/admin/reports/summary",

                "incident_endpoint":
                    "/admin/reports/incidents",

                "threat_endpoint":
                    "/admin/reports/threats",
            },
        }

    except Exception as error:

        print(
            "Admin Statistics Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load admin statistics"
            ),
        )


# ==================================================
# ADMIN RECENT
# ==================================================

@app.get("/admin/recent")
def admin_recent_activity(
    admin: str = Depends(
        verify_admin_token
    ),
):

    def recent(
        table_name,
        columns,
        limit=10,
        order_column="created_at",
    ):

        try:

            return (
                supabase
                .table(
                    table_name
                )
                .select(
                    columns
                )
                .order(
                    order_column,
                    desc=True,
                )
                .limit(
                    limit
                )
                .execute()
                .data
                or []
            )

        except Exception as error:

            print(
                f"{table_name} Recent Warning:",
                error,
            )

            return []

    return {
        "admin":
            admin,

        "url_scans":
            recent(
                "url_scans",
                (
                    "id,url,prediction,"
                    "confidence,created_at"
                ),
            ),

        "file_scans":
            recent(
                "file_scans",
                (
                    "id,file_name,prediction,"
                    "risk_level,risk_score,"
                    "created_at"
                ),
            ),

        "login_scans":
            recent(
                "login_scans",
                (
                    "id,user_identifier,"
                    "ip_address,prediction,"
                    "risk_level,risk_score,"
                    "created_at"
                ),
            ),

        "qr_scans":
            recent(
                "qr_scans",
                (
                    "id,file_name,decoded_type,"
                    "extracted_url,prediction,"
                    "risk_level,risk_score,"
                    "created_at"
                ),
            ),

        "email_scans":
            recent(
                "email_scans",
                (
                    "id,sender_email,subject,"
                    "prediction,risk_level,"
                    "risk_score,created_at"
                ),
            ),

        "security_scores":
            recent(
                "security_scores",
                "*",
                20,
                "updated_at",
            ),

        "security_events":
            recent(
                "security_events",
                "*",
                30,
            ),

        "incidents":
            recent(
                "incidents",
                "*",
                20,
                "last_detected_at",
            ),
    }


# ==================================================
# ADMIN SECURITY EVENTS
# ==================================================

@app.get(
    "/admin/security-events"
)
def admin_security_events(
    limit: int = 50,
    admin: str = Depends(
        verify_admin_token
    ),
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            200,
        ),
    )

    try:

        records = (
            supabase
            .table(
                "security_events"
            )
            .select("*")
            .order(
                "created_at",
                desc=True,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        return {
            "admin":
                admin,

            "count":
                len(
                    records
                ),

            "events":
                records,
        }

    except Exception as error:

        print(
            "Admin Security Events Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load security events"
            ),
        )


# ==================================================
# ADMIN THREAT INTELLIGENCE
# ==================================================

@app.get(
    "/admin/threat-intelligence"
)
def admin_threat_intelligence(
    limit: int = 100,
    admin: str = Depends(
        verify_admin_token
    ),
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            500,
        ),
    )

    try:

        records = (
            supabase
            .table(
                "threat_intelligence"
            )
            .select("*")
            .order(
                "last_seen_at",
                desc=True,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        return {
            "admin":
                admin,

            "count":
                len(
                    records
                ),

            "source":
                "CyberShield Internal",

            "indicators":
                records,
        }

    except Exception as error:

        print(
            "Admin Threat Intelligence Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load threat intelligence"
            ),
        )


# ==================================================
# ADMIN INCIDENT CENTER
# ==================================================

@app.get(
    "/admin/incidents"
)
def admin_incidents(
    limit: int = 50,
    status: Optional[str] = None,
    admin: str = Depends(
        verify_admin_token
    ),
):

    limit = max(
        1,
        min(
            int(
                limit
            ),
            200,
        ),
    )

    try:

        query = (
            supabase
            .table(
                "incidents"
            )
            .select("*")
        )

        if status:

            normalized = (
                str(
                    status
                )
                .strip()
                .upper()
            )

            if normalized not in {
                "OPEN",
                "INVESTIGATING",
                "RESOLVED",
            }:

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "status must be OPEN, "
                        "INVESTIGATING or RESOLVED"
                    ),
                )

            query = (
                query.eq(
                    "status",
                    normalized,
                )
            )

        incidents = (
            query
            .order(
                "last_detected_at",
                desc=True,
            )
            .limit(
                limit
            )
            .execute()
            .data
            or []
        )

        return {
            "admin":
                admin,

            "count":
                len(
                    incidents
                ),

            "incidents":
                incidents,
        }

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Admin Incidents Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load incidents"
            ),
        )


@app.get(
    "/admin/incidents/{incident_id}"
)
def admin_incident_detail(
    incident_id: int,
    admin: str = Depends(
        verify_admin_token
    ),
):

    try:

        rows = (
            supabase
            .table(
                "incidents"
            )
            .select("*")
            .eq(
                "id",
                incident_id,
            )
            .limit(1)
            .execute()
            .data
            or []
        )

        if not rows:

            raise HTTPException(
                status_code=404,
                detail=(
                    "Incident not found"
                ),
            )

        links = (
            supabase
            .table(
                "incident_events"
            )
            .select(
                "security_event_id"
            )
            .eq(
                "incident_id",
                incident_id,
            )
            .execute()
            .data
            or []
        )

        event_ids = [
            row[
                "security_event_id"
            ]
            for row
            in links
            if row.get(
                "security_event_id"
            )
            is not None
        ]

        timeline = []

        if event_ids:

            timeline = (
                supabase
                .table(
                    "security_events"
                )
                .select("*")
                .in_(
                    "id",
                    event_ids,
                )
                .order(
                    "created_at",
                    desc=False,
                )
                .execute()
                .data
                or []
            )

        return {
            "admin":
                admin,

            "incident":
                rows[0],

            "timeline":
                timeline,
        }

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Admin Incident Detail Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load incident details"
            ),
        )


@app.patch(
    "/admin/incidents/{incident_id}/status"
)
def update_incident_status(
    incident_id: int,
    data: IncidentStatusRequest,
    admin: str = Depends(
        verify_admin_token
    ),
):

    normalized = (
        str(
            data.status
        )
        .strip()
        .upper()
    )

    if normalized not in {
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "status must be OPEN, "
                "INVESTIGATING or RESOLVED"
            ),
        )

    try:

        rows = (
            supabase
            .table(
                "incidents"
            )
            .update({
                "status":
                    normalized,

                "updated_at":
                    utc_now_iso(),
            })
            .eq(
                "id",
                incident_id,
            )
            .execute()
            .data
            or []
        )

        if not rows:

            exists = (
                supabase
                .table(
                    "incidents"
                )
                .select(
                    "id"
                )
                .eq(
                    "id",
                    incident_id,
                )
                .limit(1)
                .execute()
                .data
                or []
            )

            if not exists:

                raise HTTPException(
                    status_code=404,
                    detail=(
                        "Incident not found"
                    ),
                )

        return {
            "admin":
                admin,

            "incident_id":
                incident_id,

            "status":
                normalized,

            "message":
                "Incident status updated",
        }

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Incident Status Update Error:",
            error,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to update incident status"
            ),
        )