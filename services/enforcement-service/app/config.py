import os


DEFAULT_ADAPTER = os.getenv("DEFAULT_ADAPTER", "fortigate")
FORTIGATE_BASE_URL = os.getenv("FORTIGATE_BASE_URL", "https://fortigate.example.local")
FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN", "change-me")
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root")
FORTIGATE_QUARANTINE_GROUP = os.getenv("FORTIGATE_QUARANTINE_GROUP", "NON_COMPLIANT_ENDPOINTS")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
HTTP_RETRIES = int(os.getenv("HTTP_RETRIES", "3"))
