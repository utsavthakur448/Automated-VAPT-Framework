import re


def normalize_version(version):
    """Convert a software version into a comparable numeric tuple."""
    parts = []

    for part in version.split("."):
        number = ""

        for char in part:
            if char.isdigit():
                number += char
            else:
                break

        parts.append(int(number) if number else 0)

    return tuple(parts)


def normalize_package_version(version):
    """Extract the upstream version and Debian/Ubuntu package revision."""
    match = re.match(r"^(.+?)-(\d.*)$", version)

    if not match:
        return {"upstream": version, "package": ""}

    return {
        "upstream": match.group(1),
        "package": match.group(2)
    }


def package_revision_tuple(package_version):
    """Convert a package revision into a comparable numeric tuple."""
    numbers = re.findall(r"\d+", package_version)
    return tuple(int(number) for number in numbers)


def package_version_at_least(version, fixed_version):
    """Return True when the detected package version is >= the fixed version."""
    detected = normalize_package_version(version)
    fixed = normalize_package_version(fixed_version)

    detected_upstream = normalize_version(detected["upstream"])
    fixed_upstream = normalize_version(fixed["upstream"])

    if detected_upstream != fixed_upstream:
        return detected_upstream > fixed_upstream

    detected_package = package_revision_tuple(detected["package"])
    fixed_package = package_revision_tuple(fixed["package"])

    return detected_package >= fixed_package


def version_in_range(version, minimum=None, maximum=None):
    """Check whether a software version falls within an inclusive range."""
    current = normalize_version(version)

    if minimum and current < normalize_version(minimum):
        return False

    if maximum and current > normalize_version(maximum):
        return False

    return True
