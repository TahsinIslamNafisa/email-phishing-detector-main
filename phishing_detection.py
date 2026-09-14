import re
import base64
import time
import requests
from html import unescape
from urllib.parse import urlparse

from config import VIRUSTOTAL_API_KEY


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from plain text and HTML.
    """

    if not text:
        return []

    text = unescape(text)

    # URLs inside HTML href
    html_urls = re.findall(
        r'href=["\'](https?://[^"\']+)["\']',
        text,
        flags=re.IGNORECASE
    )

    # Normal URLs
    normal_urls = re.findall(
        r'https?://[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    urls = html_urls + normal_urls

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def detect_hidden_link_mismatch(text):
    """
    Detect links where the visible URL and actual URL
    are from different domains.

    Example:

    Visible:
        https://google.com

    Actual:
        https://example.com
    """

    if not text:
        return False

    pattern = re.compile(
        r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>'
        r'(.*?)'
        r'</a>',
        flags=re.IGNORECASE | re.DOTALL
    )

    matches = pattern.findall(text)

    for actual_url, visible_text in matches:

        actual_domain = urlparse(
            actual_url
        ).netloc.lower()

        visible_urls = re.findall(
            r'https?://[^\s<>"\']+',
            visible_text
        )

        for visible_url in visible_urls:

            visible_domain = urlparse(
                visible_url
            ).netloc.lower()

            if (
                visible_domain
                and actual_domain
                and visible_domain != actual_domain
            ):

                print(
                    "\n⚠️ HIDDEN LINK MISMATCH DETECTED"
                )

                print(
                    "Visible URL:",
                    visible_url
                )

                print(
                    "Actual URL :",
                    actual_url
                )

                return True

    return False


def get_existing_report(url):
    """
    Check whether VirusTotal already has a report
    for this URL.
    """

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    try:

        response = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        return response

    except requests.exceptions.Timeout:

        print(
            "❌ VirusTotal request timed out."
        )

    except requests.exceptions.RequestException as e:

        print(
            "❌ VirusTotal request failed:"
        )

        print(e)

    return None


def submit_url_to_virustotal(url):
    """
    Submit a URL to VirusTotal for analysis.
    """

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:

        response = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={
                "url": url
            },
            timeout=20
        )

        print(
            "Submission response:",
            response.status_code
        )

        if response.status_code in [200, 201]:

            result = response.json()

            analysis_id = (
                result
                .get("data", {})
                .get("id")
            )

            print(
                "✅ URL submitted to VirusTotal."
            )

            return analysis_id

        elif response.status_code == 401:

            print(
                "❌ Invalid VirusTotal API key."
            )

        elif response.status_code == 429:

            print(
                "❌ VirusTotal API rate limit exceeded."
            )

        else:

            print(
                "❌ URL submission failed."
            )

            try:
                print(
                    response.json()
                )
            except Exception:
                pass

    except requests.exceptions.Timeout:

        print(
            "❌ VirusTotal submission timed out."
        )

    except requests.exceptions.RequestException as e:

        print(
            "❌ VirusTotal submission failed:"
        )

        print(e)

    return None


def get_analysis_result(analysis_id):
    """
    Get VirusTotal analysis result.
    """

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:

        response = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            return response.json()

        print(
            "Analysis request failed:",
            response.status_code
        )

    except Exception as e:

        print(
            "Analysis result error:",
            e
        )

    return None


def scan_new_url(url):
    """
    Submit a new URL and wait for VirusTotal analysis.
    """

    analysis_id = submit_url_to_virustotal(
        url
    )

    if not analysis_id:

        return False

    print(
        "Waiting for VirusTotal analysis..."
    )

    # Check analysis a few times
    for attempt in range(3):

        print(
            f"Checking analysis "
            f"({attempt + 1}/3)..."
        )

        time.sleep(5)

        result = get_analysis_result(
            analysis_id
        )

        if not result:

            continue

        attributes = (
            result
            .get("data", {})
            .get("attributes", {})
        )

        status = attributes.get(
            "status"
        )

        print(
            "Analysis status:",
            status
        )

        if status not in ("completed", "queued"):
            # VirusTotal reported something other than the normal
            # queued/completed lifecycle (e.g. "failed") - print the
            # raw response once so the actual reason is visible,
            # instead of silently retrying 3 times.
            print("⚠️ Unexpected VirusTotal status for URL:", url)
            print("Raw response:", result)

        if status == "completed":

            stats = attributes.get(
                "stats",
                {}
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            harmless = stats.get(
                "harmless",
                0
            )

            undetected = stats.get(
                "undetected",
                0
            )

            print(
                "Malicious  :",
                malicious
            )

            print(
                "Suspicious :",
                suspicious
            )

            print(
                "Harmless   :",
                harmless
            )

            print(
                "Undetected :",
                undetected
            )

            if malicious > 0 or suspicious > 0:

                print(
                    "🚨 MALICIOUS/SUSPICIOUS URL DETECTED!"
                )

                return True

            return False

    print(
        "ℹ️ VirusTotal analysis is still pending."
    )

    return False


def check_existing_report(url):
    """
    Check existing VirusTotal report.

    Returns:

    True  -> malicious/suspicious
    False -> existing report but not malicious
    None  -> no report found
    """

    response = get_existing_report(
        url
    )

    if response is None:

        return False

    if response.status_code == 200:

        result = response.json()

        stats = (
            result
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        harmless = stats.get(
            "harmless",
            0
        )

        undetected = stats.get(
            "undetected",
            0
        )

        print(
            "Malicious  :",
            malicious
        )

        print(
            "Suspicious :",
            suspicious
        )

        print(
            "Harmless   :",
            harmless
        )

        print(
            "Undetected :",
            undetected
        )

        if malicious > 0 or suspicious > 0:

            return True

        return False

    elif response.status_code == 404:

        print(
            "ℹ️ No existing VirusTotal report."
        )

        return None

    elif response.status_code == 401:

        print(
            "❌ Invalid VirusTotal API key."
        )

        return False

    elif response.status_code == 429:

        print(
            "❌ VirusTotal API rate limit exceeded."
        )

        return False

    else:

        print(
            "VirusTotal HTTP status:",
            response.status_code
        )

        return False


def check_url_virustotal(email_body):
    """
    Main phishing detection function.

    Returns True if phishing/suspicious activity is detected.
    """

    if not email_body:

        print(
            "Empty email body."
        )

        return False

    # ==========================================
    # STEP 1: Hidden link detection
    # ==========================================

    if detect_hidden_link_mismatch(
        email_body
    ):

        print(
            "🚨 Suspicious hidden link detected."
        )

        return True

    # ==========================================
    # STEP 2: Extract URLs
    # ==========================================

    urls = extract_urls(
        email_body
    )

    if not urls:

        print(
            "No URLs found in this email."
        )

        return False

    print(
        f"Found {len(urls)} URL(s)."
    )

    # ==========================================
    # STEP 3: Check API key
    # ==========================================

    if (
        not VIRUSTOTAL_API_KEY
        or VIRUSTOTAL_API_KEY
        == "YOUR_VIRUSTOTAL_API_KEY"
    ):

        print(
            "❌ VirusTotal API key is not configured."
        )

        return False

    # ==========================================
    # STEP 4: Scan every URL
    # ==========================================

    for url in urls:

        print(
            "\n" + "-" * 50
        )

        print(
            "Scanning URL:"
        )

        print(url)

        # --------------------------------------
        # Existing VirusTotal report
        # --------------------------------------

        existing_result = check_existing_report(
            url
        )

        # Malicious
        if existing_result is True:

            print(
                "🚨 MALICIOUS URL DETECTED!"
            )

            return True

        # Safe existing report
        if existing_result is False:

            print(
                "✅ URL is not currently flagged."
            )

            continue

        # --------------------------------------
        # No existing report
        # --------------------------------------

        print(
            "Submitting URL for new analysis..."
        )

        new_result = scan_new_url(
            url
        )

        if new_result:

            return True

    print(
        "\n" + "-" * 50
    )

    print(
        "Finished URL scanning."
    )

    return False