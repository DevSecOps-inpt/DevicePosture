import os


DEFAULT_ADAPTER = os.getenv("DEFAULT_ADAPTER", "fortigate")
FORTIGATE_BASE_URL = os.getenv("FORTIGATE_BASE_URL", "https://fortigate.example.local")
FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN", "change-me")
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root")
FORTIGATE_QUARANTINE_GROUP = os.getenv("FORTIGATE_QUARANTINE_GROUP", "NON_COMPLIANT_ENDPOINTS")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
HTTP_RETRIES = int(os.getenv("HTTP_RETRIES", "3"))
FORTIGATE_VERIFY_TLS = os.getenv("FORTIGATE_VERIFY_TLS", "true").lower() == "true"
ASYNC_DECISION_EXECUTION = os.getenv("ASYNC_DECISION_EXECUTION", "false").lower() == "true"
BACKGROUND_WORKERS = int(os.getenv("BACKGROUND_WORKERS", "4"))
HTTP_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("HTTP_CIRCUIT_BREAKER_THRESHOLD", "5"))
HTTP_CIRCUIT_BREAKER_COOLDOWN_SECONDS = int(os.getenv("HTTP_CIRCUIT_BREAKER_COOLDOWN_SECONDS", "60"))
ALLOW_POLICY_HTTP_ACTIONS = os.getenv("ALLOW_POLICY_HTTP_ACTIONS", "true").lower() == "true"
ALLOW_PRIVATE_HTTP_TARGETS = os.getenv("ALLOW_PRIVATE_HTTP_TARGETS", "true").lower() == "true"
POLICY_HTTP_ALLOWED_HOSTS = {
    item.strip().lower()
    for item in os.getenv("POLICY_HTTP_ALLOWED_HOSTS", "").split(",")
    if item.strip()
}
ADAPTER_TOKEN_MASK = "********"
