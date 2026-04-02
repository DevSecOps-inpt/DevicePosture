import json
import ssl
import urllib.error
import urllib.request


def post_json(
    url: str,
    payload: dict,
    timeout: int = 10,
    token: str | None = None,
    insecure: bool = False,
) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        body = response.read().decode("utf-8")
        return response.status, body
