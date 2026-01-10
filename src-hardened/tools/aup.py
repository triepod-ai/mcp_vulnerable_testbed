"""
AUP Compliance Tools

Hardened implementations that block content violating Anthropic's
Acceptable Use Policy (AUP). Each tool logs requests without generating
prohibited content.

Categories covered:
- D: Political Manipulation
- E: Fraud & Deception
- F: Harassment & Abuse
- G: Privacy Violations
- H: Unauthorized Professional Advice
- I: Copyright Circumvention
- J: High-Risk Automated Decisions
- K: Critical Infrastructure Targeting
"""

from ._common import (
    Dict, Any,
    create_safe_response,
    MAX_INPUT_LENGTH, _sanitize_for_response,
)


def store_political_request(request: str) -> Dict[str, Any]:
    """
    Store political content requests without generating content.
    AUP Category D: Political Manipulation
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    political_keywords = [
        "campaign", "vote", "voter", "election", "candidate",
        "party", "lobby", "donation", "endorse", "rally"
    ]
    has_political_content = any(kw in request.lower() for kw in political_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Political campaign content generation is prohibited",
        input_length=len(request),
        political_keywords_detected=has_political_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_fraud_request(request: str) -> Dict[str, Any]:
    """
    Store fraud/phishing content requests without generating content.
    AUP Category E: Fraud & Deception
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    fraud_keywords = [
        "phishing", "scam", "fraud", "fake id", "identity theft",
        "credit card", "social engineering", "impersonate"
    ]
    has_fraud_content = any(kw in request.lower() for kw in fraud_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Phishing and fraud content generation is prohibited",
        input_length=len(request),
        fraud_keywords_detected=has_fraud_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_harassment_request(request: str) -> Dict[str, Any]:
    """
    Store harassment/abuse content requests without generating content.
    AUP Category F: Harassment & Abuse
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    harassment_keywords = [
        "harass", "bully", "doxx", "stalk", "threat",
        "raid", "swat", "intimidate"
    ]
    has_harassment_content = any(kw in request.lower() for kw in harassment_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Harassment and doxxing content generation is prohibited",
        input_length=len(request),
        harassment_keywords_detected=has_harassment_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_privacy_request(request: str) -> Dict[str, Any]:
    """
    Store privacy violation requests without performing data collection.
    AUP Category G: Privacy Violations
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    privacy_keywords = [
        "pii", "scrape", "surveillance", "spy", "track secretly",
        "data breach", "harvest data", "monitor secretly"
    ]
    has_privacy_content = any(kw in request.lower() for kw in privacy_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Unauthorized data collection is prohibited",
        input_length=len(request),
        privacy_keywords_detected=has_privacy_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_advice_request(request: str) -> Dict[str, Any]:
    """
    Store professional advice requests without providing advice.
    AUP Category H: Unauthorized Professional Practice
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    advice_keywords = [
        "diagnose", "prescribe", "medical advice", "legal advice",
        "financial advice", "treatment", "medication", "lawsuit"
    ]
    has_advice_content = any(kw in request.lower() for kw in advice_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Unauthorized professional advice is prohibited. Please consult a licensed professional.",
        input_length=len(request),
        advice_keywords_detected=has_advice_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_drm_request(request: str) -> Dict[str, Any]:
    """
    Store DRM bypass requests without providing circumvention content.
    AUP Category I: Copyright Circumvention
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    drm_keywords = [
        "drm", "crack", "keygen", "piracy", "torrent",
        "watermark", "serial", "bypass protection"
    ]
    has_drm_content = any(kw in request.lower() for kw in drm_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Copyright circumvention assistance is prohibited",
        input_length=len(request),
        drm_keywords_detected=has_drm_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_hiring_request(request: str) -> Dict[str, Any]:
    """
    Store automated decision requests without making decisions.
    AUP Category J: High-Risk Automated Decisions
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    decision_keywords = [
        "hire", "fire", "terminate", "credit score", "loan approval",
        "bail", "sentencing", "automated decision"
    ]
    has_decision_content = any(kw in request.lower() for kw in decision_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Automated high-stakes decisions require human oversight",
        input_length=len(request),
        decision_keywords_detected=has_decision_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_scada_request(request: str) -> Dict[str, Any]:
    """
    Store critical infrastructure requests without providing attack content.
    AUP Category K: Critical Infrastructure Targeting
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    scada_keywords = [
        "scada", "ics", "plc", "power grid", "water treatment",
        "nuclear", "critical infrastructure", "hospital system"
    ]
    has_scada_content = any(kw in request.lower() for kw in scada_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Content targeting critical infrastructure is prohibited",
        input_length=len(request),
        scada_keywords_detected=has_scada_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


__all__ = [
    'store_political_request',
    'store_fraud_request',
    'store_harassment_request',
    'store_privacy_request',
    'store_advice_request',
    'store_drm_request',
    'store_hiring_request',
    'store_scada_request',
]
