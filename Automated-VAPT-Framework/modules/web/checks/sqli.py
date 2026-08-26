from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from modules.vulnerabilities.models import Finding


SQL_ERROR_MARKERS = {
    "mysql": [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "mysqli",
        "mysql_num_rows",
        "warning: mysql"
    ],
    "postgresql": [
        "postgresql",
        "pg_query",
        "pg_exec",
        "syntax error at or near"
    ],
    "mssql": [
        "microsoft sql server",
        "odbc sql server driver",
        "sqlserver",
        "unclosed quotation mark"
    ],
    "oracle": [
        "ora-",
        "oracle database",
        "oracle error"
    ],
    "sqlite": [
        "sqlite error",
        "sqlite3.operationalerror",
        "near \""
    ]
}


def find_sql_error(body):
    if not body:
        return None

    body_lower = body.lower()

    for database, markers in SQL_ERROR_MARKERS.items():
        for marker in markers:
            if marker in body_lower:
                return database

    return None


def check_sql_error(scanner, url, parameter="id"):
    """
    Safe SQL error-based indicator.

    A harmless malformed value is supplied to a single parameter
    and the response is checked for common database error messages.

    This does NOT confirm SQL injection.
    Manual validation is required.
    """

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = ["NEXUS_SQL_TEST'"]

    new_query = urlencode(query, doseq=True)

    test_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    response = scanner.scan_url(test_url)

    if not response or response.error:
        return None

    database = find_sql_error(response.body)

    if not database:
        return None

    return Finding(
        title="Potential SQL Injection",
        severity="MEDIUM",
        description=(
            "The application response contains a database error signature "
            "after malformed input was supplied to an HTTP parameter. This "
            "is an indicator only and does not confirm exploitable SQL injection."
        ),
        host=parsed.hostname or "",
        service="http",
        evidence=(
            f"Parameter: {parameter}; database error signature: {database}; "
            f"URL: {response.url}"
        ),
        remediation=(
            "Use parameterized queries or prepared statements for database "
            "access. Validate input server-side and avoid exposing database "
            "errors to users."
        )
    )
