import base64

def encode_url_to_base64(url):
    """Encodes a URL to base64 (without padding) for VirusTotal API."""
    encoded_bytes = base64.urlsafe_b64encode(url.encode("utf-8"))
    return encoded_bytes.decode("utf-8").rstrip("=")