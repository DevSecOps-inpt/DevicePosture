import argparse
import json
import logging
from pathlib import Path
import signal
import sys
import threading

from config import load_config
from runtime import collect_telemetry, maybe_write_payload, send_payload
from service import run_agent


def parse_args() -> argparse.Namespace:
    default_config = Path(__file__).with_name("example-config.toml")
    parser = argparse.ArgumentParser(description="Config-driven Windows endpoint collector agent")
    parser.add_argument("mode", nargs="?", choices=["once", "run"], default="once")
    parser.add_argument("--config", default=str(default_config), help="Path to the collector config TOML file")
    parser.add_argument("--url", help="Override the telemetry API URL")
    parser.add_argument("--token", help="Override the bearer token")
    parser.add_argument("--timeout", type=int, help="Override the HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--output", help="Write normalized telemetry JSON to a file")
    parser.add_argument("--interval-seconds", type=int, help="Override the collection interval")
    parser.add_argument("--log-level", help="Override the log level")
    parser.add_argument("--no-send", action="store_true", help="Collect locally without posting to the server")
    return parser.parse_args()


def apply_overrides(config, args: argparse.Namespace):
    if args.url:
        config.transport.url = args.url
    if args.token:
        config.transport.token = args.token
    if args.timeout:
        config.transport.timeout_seconds = args.timeout
    if args.insecure:
        config.transport.insecure_tls = True
    if args.output:
        config.agent.write_payload_file = args.output
    if args.interval_seconds:
        config.agent.interval_seconds = args.interval_seconds
    if args.log_level:
        config.agent.log_level = args.log_level
    if args.no_send:
        config.transport.enabled = False
    return config


def configure_logging(level_name: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level_name.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def run_once(config) -> int:
    payload = collect_telemetry(config)
    maybe_write_payload(payload, config.agent.write_payload_file)
    print(json.dumps(payload, indent=2))

    if config.transport.enabled and config.transport.url:
        try:
            status_code, body = send_payload(payload, config)
            print(f"POST {config.transport.url} -> {status_code}")
            if body:
                print(body)
        except Exception as exc:
            print(f"Failed to send telemetry: {exc}", file=sys.stderr)
            return 1
    return 0


def run_forever(config) -> int:
    configure_logging(config.agent.log_level)
    stop_event = threading.Event()

    def handle_stop(signum, _frame) -> None:
        logging.getLogger("endpoint_agent").info("Received signal %s, stopping agent", signum)
        stop_event.set()

    for signum in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if signum is not None:
            signal.signal(signum, handle_stop)

    run_agent(config, stop_event)
    return 0


def main() -> int:
    args = parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = (Path.cwd() / config_path).resolve()
    config = apply_overrides(load_config(config_path), args)

    if args.mode == "run":
        return run_forever(config)
    return run_once(config)


if __name__ == "__main__":
    raise SystemExit(main())
