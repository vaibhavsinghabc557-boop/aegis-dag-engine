import asyncio
import json
import math
import socket
import ssl
import time
from collections import Counter
from typing import Dict, Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="Aegis-DAG: Autonomous Cyber-Heuristic & Agentic Engine")


def calculate_shannon_entropy(data: str) -> float:
    """Computes Shannon Entropy H(X) in bits/symbol to measure payload randomness."""
    if not data:
        return 0.0
    length = len(data)
    frequencies = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


async def inspect_tls_and_socket(domain: str) -> Dict[str, Any]:
    """Performs standard TCP/TLS handshake inspection to verify certificate and cipher configuration."""
    t0 = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _sync_probe():
            with socket.create_connection((domain, 443), timeout=4.0) as sock:
                ip_addr = sock.getpeername()[0]
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher_name, tls_version, secret_bits = ssock.cipher()
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    return {
                        "resolved_ip": ip_addr,
                        "tls_version": tls_version,
                        "cipher_suite": cipher_name,
                        "key_strength_bits": secret_bits,
                        "ca_issuer": issuer.get("organizationName", "Unknown CA"),
                    }

        result = await loop.run_in_executor(None, _sync_probe)
        result["handshake_latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return result
    except Exception as e:
        return {"error": str(e), "handshake_latency_ms": round((time.perf_counter() - t0) * 1000, 2)}


async def audit_http_security_surface(target_url: str) -> Dict[str, Any]:
    """Checks standard defensive HTTP response headers for best-practice compliance."""
    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(target_url)
            headers = resp.headers

            security_matrix = {
                "Strict-Transport-Security": "PASS" if "strict-transport-security" in headers else "MISSING (Recommend HSTS)",
                "Content-Security-Policy": "PASS" if "content-security-policy" in headers else "MISSING (Recommend CSP)",
                "X-Frame-Options": "PASS" if "x-frame-options" in headers else "MISSING (Recommend X-Frame-Options)",
                "X-Content-Type-Options": "PASS" if "x-content-type-options" in headers else "MISSING (Recommend nosniff)",
            }

            body_sample = resp.text[:4096]
            entropy = round(calculate_shannon_entropy(body_sample), 4)
            score = sum(25 for v in security_matrix.values() if v == "PASS")

            return {
                "http_status": resp.status_code,
                "server_banner": headers.get("server", "Hidden / Not Disclosed"),
                "hardening_score": f"{score}/100",
                "payload_shannon_entropy": f"{entropy} bits/byte",
                "owasp_header_audit": security_matrix,
                "rtt_ms": round((time.perf_counter() - t0) * 1000, 2),
            }
    except Exception as e:
        return {"error": str(e)}


async def execute_agent_dag(ws: WebSocket, target_input: str):
    """Streams real-time multi-node DAG state transitions to the frontend over WebSockets."""
    clean_domain = (
        urlparse(target_input).netloc
        or target_input.replace("https://", "").replace("http://", "").split("/")[0]
    )

    async def emit(node: str, status: str, payload: Any):
        await ws.send_text(json.dumps({
            "timestamp": round(time.time(), 3),
            "dag_node": node,
            "state": status,
            "telemetry": payload
        }))
        await asyncio.sleep(0.35)

    await emit("NODE_01_PLANNER", "INITIALIZING", {
        "target": clean_domain,
        "execution_graph": [
            "TLS_SOCKET_INSPECTION",
            "HTTP_HEADER_COMPLIANCE",
            "SHANNON_ENTROPY_CALCULATION",
            "DEFENSIVE_POSTURE_SUMMARY"
        ]
    })

    await emit("NODE_02_PARALLEL_EXECUTOR", "RUNNING", {
        "message": "Dispatching concurrent async coroutines..."
    })
    tls_task = asyncio.create_task(inspect_tls_and_socket(clean_domain))
    http_task = asyncio.create_task(audit_http_security_surface(clean_domain))

    tls_data, http_data = await asyncio.gather(tls_task, http_task)

    await emit("NODE_03_TLS_CRYPTO_TELEMETRY", "COMPLETED", tls_data)
    await emit("NODE_04_OWASP_HEADER_MATRIX", "COMPLETED", http_data)

    synthesis = {
        "target_host": clean_domain,
        "cryptographic_posture": "HIGH_ASSURANCE" if tls_data.get("tls_version") == "TLSv1.3" else "STANDARD_OR_LEGACY",
        "recommended_remediation": [
            k for k, v in http_data.get("owasp_header_audit", {}).items() if "MISSING" in v
        ] or ["All primary defensive HTTP headers enforced."]
    }
    await emit("NODE_05_SYNTHESIS_ENGINE", "TERMINATED_OK", synthesis)


HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis-DAG // Autonomous Telemetry Orchestrator</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { background-color: #06080d; color: #e2e8f0; font-family: 'Courier New', monospace; }
  .glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.2); }
</style>
</head>
<body class="p-4 md:p-8 min-h-screen">
  <div class="max-w-4xl mx-auto">
    <div class="glass rounded-xl p-6 mb-6 shadow-2xl">
      <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
        <div>
          <span class="text-xs px-2 py-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">DAG ENGINE v2.6 // ONLINE</span>
          <h1 class="text-2xl font-bold text-white mt-2">Aegis-DAG Autonomous Defensive Telemetry Agent</h1>
          <p class="text-xs text-slate-400">Architected by Vaibhav Singh | Async Python + Shannon Entropy + TLS Inspection</p>
        </div>
      </div>
      <div class="flex flex-col sm:flex-row gap-2">
        <input id="target" type="text" value="github.com" placeholder="Enter domain (e.g., github.com, cloudflare.com)" 
               class="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-cyan-300 focus:outline-none focus:border-cyan-500">
        <button onclick="runDag()" class="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-5 py-2.5 rounded-lg text-sm transition">
          EXECUTE DAG
        </button>
      </div>
    </div>

    <div id="stream" class="space-y-3"></div>
  </div>

<script>
  let ws;
  function runDag() {
    const stream = document.getElementById('stream');
    stream.innerHTML = '';
    const target = document.getElementById('target').value;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);
    ws.onopen = () => ws.send(target);
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const card = document.createElement('div');
      card.className = 'glass rounded-lg p-4 text-xs transition-all duration-300';
      card.innerHTML = `
        <div class="flex justify-between text-cyan-400 font-bold mb-2">
          <span>[${data.dag_node}]</span>
          <span class="text-emerald-400">${data.state}</span>
        </div>
        <pre class="text-slate-300 overflow-x-auto">${JSON.stringify(data.telemetry, null, 2)}</pre>
      `;
      stream.appendChild(card);
    };
  }
</script>
</body>
</html>
"""


@app.get("/")
async def serve_ui():
    return HTMLResponse(HTML_DASHBOARD)


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        target = await websocket.receive_text()
        await execute_agent_dag(websocket, target.strip())
    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
                                          
