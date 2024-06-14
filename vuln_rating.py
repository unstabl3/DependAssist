def determine_cvss_severity(cvss_score):
    """Determine CVSS severity level based on the CVSS score."""
    if cvss_score is None:
        return "Unknown"
    elif cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"

def calculate_severity(cvss_score, epss_score, kev_status):
    """Calculate the final severity based on CVSS score, EPSS score, and KEV status."""
    cvss_severity = determine_cvss_severity(cvss_score)

    if cvss_score is None:
        return "P4"

    epss_score = float(epss_score) if epss_score is not None else 0.0

    if cvss_severity == "Low":
        return "P4"
    elif cvss_severity == "Medium":
        if kev_status:
            return "P4"
        elif epss_score < 0.088:
            return "P4"
        else:
            return "P4"
    elif cvss_severity == "High":
        if kev_status:
            return "P3"
        elif epss_score >= 0.088:
            return "P4"
        else:
            return "P4"
    elif cvss_severity == "Critical":
        if kev_status:
            return "P3"
        elif epss_score >= 0.088:
            return "P3"
        else:
            return "P4"
