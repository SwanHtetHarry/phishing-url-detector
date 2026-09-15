import base64
import requests


VT_BASE_URL = "https://www.virustotal.com/api/v3"


# =========================================================
# CREATE VIRUSTOTAL URL ID
# =========================================================

def create_url_id(url):
    """
    Convert a URL into the URL-safe Base64 ID
    used by VirusTotal.
    """

    return (
        base64.urlsafe_b64encode(
            url.encode()
        )
        .decode()
        .strip("=")
    )


# =========================================================
# GET EXISTING URL REPORT
# =========================================================

def get_url_report(url, api_key):
    """
    Look up an existing VirusTotal report.

    This does NOT submit a new scan.
    """

    url_id = create_url_id(url)

    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:

            return {
                "found": False,
                "message": (
                    "No existing VirusTotal report was found."
                )
            }

        response.raise_for_status()

        data = response.json()

        attributes = (
            data["data"]["attributes"]
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "found": True,
            "malicious": stats.get(
                "malicious", 0
            ),
            "suspicious": stats.get(
                "suspicious", 0
            ),
            "harmless": stats.get(
                "harmless", 0
            ),
            "undetected": stats.get(
                "undetected", 0
            ),
            "timeout": stats.get(
                "timeout", 0
            )
        }

    except requests.exceptions.RequestException as error:

        return {
            "found": False,
            "error": str(error)
        }


# =========================================================
# SUBMIT URL FOR FRESH SCAN
# =========================================================

def submit_url_scan(url, api_key):
    """
    Submit a URL to VirusTotal for fresh analysis.
    """

    endpoint = f"{VT_BASE_URL}/urls"

    headers = {
        "x-apikey": api_key
    }

    data = {
        "url": url
    }

    try:

        response = requests.post(
            endpoint,
            headers=headers,
            data=data,
            timeout=15
        )

        response.raise_for_status()

        result = response.json()

        return {
            "success": True,
            "analysis_id": (
                result["data"]["id"]
            )
        }

    except requests.exceptions.RequestException as error:

        return {
            "success": False,
            "error": str(error)
        }


# =========================================================
# CHECK ANALYSIS STATUS
# =========================================================

def get_analysis_status(
    analysis_id,
    api_key
):
    """
    Check the status of a submitted VirusTotal analysis.
    """

    endpoint = (
        f"{VT_BASE_URL}/analyses/"
        f"{analysis_id}"
    )

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        attributes = (
            data["data"]["attributes"]
        )

        return {
            "success": True,
            "status": attributes.get(
                "status"
            ),
            "stats": attributes.get(
                "stats",
                {}
            )
        }

    except requests.exceptions.RequestException as error:

        return {
            "success": False,
            "error": str(error)
        }