from modules.risk.cvss import cvss_severity

def calculate_severity(cvss):
    """Calculate severity from a CVSS score."""
    return cvss_severity(cvss)

def calculate_priority(severity, cvss):
    """Convert severity/CVSS into an operational remediation priority."""
    if severity == "CRITICAL":
        return "IMMEDIATE" if cvss >= 9.5 else "URGENT"

    if severity == "HIGH":
        return "HIGH"

    if severity == "MEDIUM":
        return "MEDIUM"

    if severity == "LOW":
        return "LOW"

    if severity == "INFO":
        return "INFORMATIONAL"

    return "UNKNOWN"
