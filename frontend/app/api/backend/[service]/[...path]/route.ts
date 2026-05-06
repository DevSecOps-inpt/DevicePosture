import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const SERVICE_BASE_URLS = {
  telemetry: process.env.TELEMETRY_API_URL ?? "http://127.0.0.1:8011",
  policy: process.env.POLICY_SERVICE_URL ?? "http://127.0.0.1:8002",
  evaluation: process.env.EVALUATION_ENGINE_URL ?? "http://127.0.0.1:8003",
  enforcement: process.env.ENFORCEMENT_SERVICE_URL ?? "http://127.0.0.1:8004"
} as const;

type BackendService = keyof typeof SERVICE_BASE_URLS;

const HOP_BY_HOP_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);

function isBackendService(service: string): service is BackendService {
  return service in SERVICE_BASE_URLS;
}

function rejectUnsafePathSegment(segment: string): boolean {
  const value = segment.trim().toLowerCase();
  return (
    value.includes("://") ||
    value.startsWith("http:") ||
    value.startsWith("https:") ||
    value.includes("\\")
  );
}

function buildBackendUrl(service: BackendService, pathSegments: string[], search: string): string {
  if (pathSegments.some(rejectUnsafePathSegment)) {
    throw new Error("Absolute or external URLs are not allowed");
  }
  const baseUrl = SERVICE_BASE_URLS[service].replace(/\/+$/, "");
  const safePath = pathSegments.map((segment) => encodeURIComponent(segment)).join("/");
  return `${baseUrl}/${safePath}${search}`;
}

function buildForwardHeaders(request: NextRequest, service: BackendService, hasBody: boolean): Headers {
  const headers = new Headers();
  const accept = request.headers.get("accept");
  if (accept) {
    headers.set("accept", accept);
  }
  if (hasBody) {
    headers.set("content-type", request.headers.get("content-type") ?? "application/json");
  }
  if (service === "policy") {
    const cookie = request.headers.get("cookie");
    if (cookie) {
      headers.set("cookie", cookie);
    }
  }
  const apiKey = process.env.POSTURE_API_KEY?.trim();
  if (apiKey) {
    headers.set("x-api-key", apiKey);
  }
  return headers;
}

function buildResponseHeaders(backendResponse: Response): Headers {
  const headers = new Headers();
  backendResponse.headers.forEach((value, key) => {
    const normalizedKey = key.toLowerCase();
    if (HOP_BY_HOP_RESPONSE_HEADERS.has(normalizedKey)) {
      return;
    }
    if (["content-type", "set-cookie", "cache-control"].includes(normalizedKey)) {
      headers.set(key, value);
    }
  });
  headers.set("cache-control", "no-store");
  return headers;
}

async function proxyRequest(
  request: NextRequest,
  { params }: { params: { service: string; path?: string[] } }
): Promise<Response> {
  if (!isBackendService(params.service)) {
    return Response.json({ detail: "Unknown backend service" }, { status: 404 });
  }

  const method = request.method.toUpperCase();
  const hasBody = !["GET", "HEAD"].includes(method);
  let targetUrl: string;
  try {
    targetUrl = buildBackendUrl(params.service, params.path ?? [], request.nextUrl.search);
  } catch (error) {
    return Response.json(
      { detail: error instanceof Error ? error.message : "Invalid backend path" },
      { status: 400 }
    );
  }

  let backendResponse: Response;
  try {
    backendResponse = await fetch(targetUrl, {
      method,
      headers: buildForwardHeaders(request, params.service, hasBody),
      body: hasBody ? await request.text() : undefined,
      cache: "no-store"
    });
  } catch (error) {
    return Response.json(
      {
        detail: "Backend service is unreachable",
        service: params.service,
        reason: error instanceof Error ? error.message : "Unknown network error"
      },
      { status: 502 }
    );
  }

  const body = backendResponse.status === 204 ? null : await backendResponse.text();
  return new Response(body, {
    status: backendResponse.status,
    statusText: backendResponse.statusText,
    headers: buildResponseHeaders(backendResponse)
  });
}

export function GET(request: NextRequest, context: { params: { service: string; path?: string[] } }) {
  return proxyRequest(request, context);
}

export function POST(request: NextRequest, context: { params: { service: string; path?: string[] } }) {
  return proxyRequest(request, context);
}

export function PUT(request: NextRequest, context: { params: { service: string; path?: string[] } }) {
  return proxyRequest(request, context);
}

export function PATCH(request: NextRequest, context: { params: { service: string; path?: string[] } }) {
  return proxyRequest(request, context);
}

export function DELETE(request: NextRequest, context: { params: { service: string; path?: string[] } }) {
  return proxyRequest(request, context);
}
