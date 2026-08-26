def validate_cvss(score):
    """Validate a CVSS score from 0.0 to 10.0."""
    if score is None:
        return None

    try:
        score = float(score)
    except (TypeError, ValueError):
        return None

    if not 0.0 <= score <= 10.0:
        return None

    return round(score, 1)


def cvss_severity(score):
    """Convert a CVSS score into a severity level."""
    score = validate_cvss(score)

    if score is None:
        return "UNKNOWN"
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"

    return "CRITICAL"
