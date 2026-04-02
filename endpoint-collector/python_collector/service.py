from __future__ import annotations

import logging
import threading
import time

from config import EndpointCollectorConfig
from runtime import collect_telemetry, maybe_write_payload, send_payload


def run_agent(config: EndpointCollectorConfig, stop_event: threading.Event) -> None:
    logger = logging.getLogger("endpoint_agent")
    interval = max(10, int(config.agent.interval_seconds))

    logger.info("Endpoint agent started with %s second interval", interval)
    logger.info("Enabled collectors: %s", ", ".join(config.collectors.enabled))

    while not stop_event.is_set():
        started = time.monotonic()
        try:
            payload = collect_telemetry(config)
            maybe_write_payload(payload, config.agent.write_payload_file)
            response = send_payload(payload, config)
            if response is None:
                logger.info("Collected telemetry for %s without sending", payload.get("endpoint_id"))
            else:
                status_code, body = response
                logger.info(
                    "Collected and sent telemetry for %s with HTTP %s",
                    payload.get("endpoint_id"),
                    status_code,
                )
                if body:
                    logger.debug("Server response: %s", body)
        except Exception as exc:
            logger.exception("Collector cycle failed: %s", exc)

        elapsed = time.monotonic() - started
        sleep_seconds = max(1, interval - int(elapsed))
        stop_event.wait(sleep_seconds)
