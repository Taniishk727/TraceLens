"""
============================================================
TraceLens Site Database Validator
============================================================

Validates the username site database before investigations
are executed.

Checks
------
✓ Required fields
✓ Duplicate names
✓ Duplicate URLs
✓ Valid detector
✓ URL placeholder
✓ Timeout values

Author:
TraceLens
"""

from app.osint.data.username_sites import SITES
from app.osint.detectors.registry import list_detectors


# ==========================================================
# REQUIRED CONFIGURATION
# ==========================================================

REQUIRED_FIELDS = {

    "name",

    "category",

    "url",

    "detector",

    "timeout"

}


# ==========================================================
# VALIDATOR
# ==========================================================

def validate_sites():

    errors = []

    warnings = []

    names = set()

    urls = set()

    registered_detectors = set(list_detectors())

    for index, site in enumerate(SITES):

        site_name = site.get(
            "name",
            f"Site #{index + 1}"
        )

        # --------------------------------------------------
        # Required Fields
        # --------------------------------------------------

        missing = REQUIRED_FIELDS - site.keys()

        if missing:

            errors.append({

                "site": site_name,

                "type": "Missing Fields",

                "message": f"Missing fields: {sorted(missing)}"

            })

        # --------------------------------------------------
        # Duplicate Name
        # --------------------------------------------------

        if site.get("name") in names:

            errors.append({

                "site": site_name,

                "type": "Duplicate Name",

                "message": "Duplicate site name."

            })

        else:

            names.add(site.get("name"))

        # --------------------------------------------------
        # Duplicate URL
        # --------------------------------------------------

        if site.get("url") in urls:

            errors.append({

                "site": site_name,

                "type": "Duplicate URL",

                "message": "Duplicate profile URL."

            })

        else:

            urls.add(site.get("url"))

        # --------------------------------------------------
        # URL Placeholder
        # --------------------------------------------------

        if "{}" not in site.get("url", ""):

            errors.append({

                "site": site_name,

                "type": "Invalid URL",

                "message": "URL must contain '{}' placeholder."

            })

        # --------------------------------------------------
        # Detector Exists
        # --------------------------------------------------

        detector = site.get("detector")

        if detector not in registered_detectors:

            errors.append({

                "site": site_name,

                "type": "Unknown Detector",

                "message": f"'{detector}' is not registered."

            })
        
                # --------------------------------------------------
        # Detector-Specific Validation
        # --------------------------------------------------

        if detector == "status":

            if "expected" not in site:

                errors.append({

                    "site": site_name,

                    "type": "Missing Field",

                    "message": "Status detector requires 'expected'."

                })

            elif not isinstance(site["expected"], int):

                errors.append({

                    "site": site_name,

                    "type": "Invalid Field",

                    "message": "'expected' must be an integer."

                })


        elif detector == "html":

            if "found" not in site:

                errors.append({

                    "site": site_name,

                    "type": "Missing Field",

                    "message": "HTML detector requires 'found'."

                })

            elif not isinstance(site["found"], list):

                errors.append({

                    "site": site_name,

                    "type": "Invalid Field",

                    "message": "'found' must be a list."

                })

            if "not_found" not in site:

                errors.append({

                    "site": site_name,

                    "type": "Missing Field",

                    "message": "HTML detector requires 'not_found'."

                })

            elif not isinstance(site["not_found"], list):

                errors.append({

                    "site": site_name,

                    "type": "Invalid Field",

                    "message": "'not_found' must be a list."

                })


        elif detector == "redirect":

            if "redirect_not_found" not in site:

                errors.append({

                    "site": site_name,

                    "type": "Missing Field",

                    "message": "Redirect detector requires 'redirect_not_found'."

                })

            elif not isinstance(site["redirect_not_found"], list):

                errors.append({

                    "site": site_name,

                    "type": "Invalid Field",

                    "message": "'redirect_not_found' must be a list."

                })

        # --------------------------------------------------
        # Timeout
        # --------------------------------------------------

        timeout = site.get("timeout")

        if not isinstance(timeout, (int, float)):

            errors.append({

                "site": site_name,

                "type": "Invalid Timeout",

                "message": "Timeout must be numeric."

            })

        elif timeout <= 0:

            errors.append({

                "site": site_name,

                "type": "Invalid Timeout",

                "message": "Timeout must be greater than zero."

            })

        elif timeout > 30:

            warnings.append({

                "site": site_name,

                "type": "Large Timeout",

                "message": "Timeout exceeds 30 seconds."

            })

    return {

        "valid": len(errors) == 0,

        "total_sites": len(SITES),

        "registered_detectors": len(registered_detectors),

        "errors": errors,

        "warnings": warnings,

        "error_count": len(errors),

        "warning_count": len(warnings)

    }


# ==========================================================
# CLI
# ==========================================================

if __name__ == "__main__":

    report = validate_sites()

    print("=" * 60)

    print("TraceLens Site Validator")

    print("=" * 60)

    print(f"Total Sites : {report['total_sites']}")

    print(f"Detectors   : {report['registered_detectors']}")

    print(f"Errors      : {report['error_count']}")

    print(f"Warnings    : {report['warning_count']}")

    print()

    if report["valid"]:

        print("✓ Site database validation successful.")

    else:

        print("✗ Validation failed.\n")

        for error in report["errors"]:

            print(
                f"[ERROR] {error['site']} :: "
                f"{error['type']} -> "
                f"{error['message']}"
            )

        print()

        for warning in report["warnings"]:

            print(
                f"[WARNING] {warning['site']} :: "
                f"{warning['message']}"
            )
    