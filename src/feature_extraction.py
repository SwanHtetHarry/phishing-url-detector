import re
import ipaddress
from urllib.parse import urlparse


def extract_url_features(url):
    # Make sure URL is a string
    url = str(url).strip()

    # Used only for parsing domains when user enters something like google.com
    parse_url = url if "://" in url else "//" + url
    parsed = urlparse(parse_url)

    domain = parsed.hostname or ""

    # -------------------------
    # Basic URL information
    # -------------------------

    url_length = len(url)
    domain_length = len(domain)

    # Check whether domain is an IP address
    try:
        ipaddress.ip_address(domain)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    # -------------------------
    # TLD and subdomains
    # -------------------------

    domain_parts = domain.split(".") if domain else []

    if is_domain_ip == 0 and len(domain_parts) >= 2:
        tld_length = len(domain_parts[-1])
        no_of_subdomain = max(0, len(domain_parts) - 2)
    else:
        tld_length = 0
        no_of_subdomain = 0

    # -------------------------
    # Obfuscation
    # Example: %20, %3D, %2F
    # -------------------------

    encoded_patterns = re.findall(r"%[0-9A-Fa-f]{2}", url)

    no_of_obfuscated_char = len(encoded_patterns) * 3
    has_obfuscation = int(no_of_obfuscated_char > 0)

    obfuscation_ratio = (
        no_of_obfuscated_char / url_length
        if url_length > 0
        else 0
    )

    # -------------------------
    # Letters and digits
    # -------------------------

    no_of_letters = sum(c.isalpha() for c in url)
    no_of_digits = sum(c.isdigit() for c in url)

    letter_ratio = (
        no_of_letters / url_length
        if url_length > 0
        else 0
    )

    digit_ratio = (
        no_of_digits / url_length
        if url_length > 0
        else 0
    )

    # -------------------------
    # Symbols
    # -------------------------

    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")

    # Other unusual characters
    normal_url_symbols = ".:/?=&"

    no_of_other_special_chars = sum(
        not c.isalnum() and c not in normal_url_symbols
        for c in url
    )

    # All non-alphanumeric characters
    special_char_count = sum(
        not c.isalnum()
        for c in url
    )

    special_char_ratio = (
        special_char_count / url_length
        if url_length > 0
        else 0
    )

    # -------------------------
    # HTTPS
    # -------------------------

    is_https = int(parsed.scheme.lower() == "https")

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_of_digits,
        "DigitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": no_of_other_special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": is_https
    }