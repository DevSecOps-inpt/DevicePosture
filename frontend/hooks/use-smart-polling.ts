"use client";

import { useEffect, useRef } from "react";

type SmartPollingOptions = {
  enabled?: boolean;
  runImmediately?: boolean;
  visibleIntervalMs?: number;
  hiddenIntervalMs?: number;
};

export function useSmartPolling(
  callback: () => Promise<void> | void,
  {
    enabled = true,
    runImmediately = true,
    visibleIntervalMs = 10000,
    hiddenIntervalMs = 45000
  }: SmartPollingOptions = {}
) {
  const callbackRef = useRef(callback);
  const inFlightRef = useRef(false);
  const timerRef = useRef<number | null>(null);

  callbackRef.current = callback;

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let disposed = false;

    const clearTimer = () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };

    const nextDelay = () => (document.visibilityState === "visible" ? visibleIntervalMs : hiddenIntervalMs);

    const run = async () => {
      if (disposed || inFlightRef.current) {
        return;
      }
      inFlightRef.current = true;
      try {
        await callbackRef.current();
      } finally {
        inFlightRef.current = false;
      }
    };

    const schedule = () => {
      clearTimer();
      timerRef.current = window.setTimeout(async () => {
        await run();
        if (!disposed) {
          schedule();
        }
      }, nextDelay());
    };

    const handleVisibilityChange = () => {
      if (disposed) {
        return;
      }
      schedule();
      if (document.visibilityState === "visible") {
        void run();
      }
    };

    if (runImmediately) {
      void run();
    }
    schedule();
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", handleVisibilityChange);

    return () => {
      disposed = true;
      clearTimer();
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("focus", handleVisibilityChange);
    };
  }, [enabled, hiddenIntervalMs, runImmediately, visibleIntervalMs]);
}
