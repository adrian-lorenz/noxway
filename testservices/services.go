package testservices

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func Testservice1(c *gin.Context) {
	if websocket.IsWebSocketUpgrade(c.Request) {
		conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if err := conn.WriteMessage(msgType, msg); err != nil {
				break
			}
		}
		return
	}
	c.JSON(200, gin.H{
		"message": "Testservice1",
		"headers": c.Request.Header,
		"ip":      c.ClientIP(),
	})
}

func Testservice2(c *gin.Context) {

	c.JSON(200, gin.H{
		"message": "Testservice2",
		"headers": c.Request.Header,
		"ip":      c.ClientIP(),
	})
}

func Testservice3(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(200, testservice3HTML)
}

func Testservice3Info(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Testservice3",
		"headers": c.Request.Header,
		"ip":      c.ClientIP(),
		"method":  c.Request.Method,
		"path":    c.Request.URL.Path,
	})
}

const testservice3HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Noxway — Frontend Testservice</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; padding: 2rem; }
    h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
    .badge { display: inline-block; background: #22c55e; color: #000; font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 999px; margin-left: 0.5rem; vertical-align: middle; }
    .badge.ws { background: #3b82f6; color: #fff; }
    .subtitle { color: #64748b; font-size: 0.875rem; margin-bottom: 2rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; max-width: 900px; }
    @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
    .card { background: #1e2330; border: 1px solid #2d3448; border-radius: 0.75rem; padding: 1.25rem; }
    .card h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.75rem; }
    pre { font-size: 0.75rem; line-height: 1.6; white-space: pre-wrap; word-break: break-all; color: #a5f3fc; }
    .ws-log { font-size: 0.75rem; line-height: 1.8; height: 120px; overflow-y: auto; }
    .ws-log .msg { color: #86efac; }
    .ws-log .err { color: #f87171; }
    .ws-log .info { color: #94a3b8; }
    button { margin-top: 0.75rem; padding: 0.4rem 1rem; border: none; border-radius: 0.4rem; font-size: 0.8rem; font-weight: 600; cursor: pointer; background: #3b82f6; color: #fff; }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    input { width: 100%; margin-top: 0.5rem; padding: 0.4rem 0.6rem; border-radius: 0.4rem; border: 1px solid #2d3448; background: #0f1117; color: #e2e8f0; font-size: 0.8rem; }
  </style>
</head>
<body>
  <h1>Noxway <span class="badge">testservice3</span> <span class="badge ws">frontend</span></h1>
  <p class="subtitle">Gateway frontend test — headers, ping, WebSocket echo</p>

  <div class="grid">
    <div class="card">
      <h2>Request Info</h2>
      <pre id="info">loading...</pre>
    </div>

    <div class="card">
      <h2>Gateway Ping</h2>
      <pre id="ping">—</pre>
      <button onclick="doPing()">Ping /v1/testservice1</button>
    </div>

    <div class="card" style="grid-column: span 2">
      <h2>WebSocket Echo <span class="badge ws">ws</span></h2>
      <div class="ws-log" id="wslog"><span class="info">not connected</span></div>
      <input id="wsmsg" placeholder="Message to send..." />
      <button id="wsconnect" onclick="wsConnect()">Connect ws://localhost:8080/v1/testservice1</button>
      <button id="wssend" onclick="wsSend()" disabled>Send</button>
    </div>
  </div>

  <script>
    // ── Request info ──────────────────────────────────────────────────────────
    fetch('/testservice3/info', { headers: { 'X-Test': 'frontend' } })
      .then(r => r.json())
      .then(d => { document.getElementById('info').textContent = JSON.stringify(d, null, 2) })
      .catch(e => { document.getElementById('info').textContent = 'error: ' + e })

    // ── Ping ──────────────────────────────────────────────────────────────────
    function doPing() {
      const t0 = Date.now()
      fetch('/v1/testservice1')
        .then(r => r.json())
        .then(d => {
          document.getElementById('ping').textContent =
            'HTTP ' + (Date.now()-t0) + 'ms\n' + JSON.stringify(d, null, 2)
        })
        .catch(e => { document.getElementById('ping').textContent = 'error: ' + e })
    }

    // ── WebSocket ─────────────────────────────────────────────────────────────
    let ws = null
    function log(cls, msg) {
      const el = document.getElementById('wslog')
      const line = document.createElement('div')
      line.className = cls
      line.textContent = new Date().toLocaleTimeString() + ' ' + msg
      el.appendChild(line)
      el.scrollTop = el.scrollHeight
    }
    function wsConnect() {
      if (ws) { ws.close(); return }
      const url = 'ws://' + location.host + '/v1/testservice1'
      log('info', 'connecting to ' + url)
      ws = new WebSocket(url)
      ws.onopen  = () => { log('msg', 'connected'); document.getElementById('wssend').disabled = false; document.getElementById('wsconnect').textContent = 'Disconnect' }
      ws.onmessage = e => log('msg', '← ' + e.data)
      ws.onerror = e => log('err', 'error')
      ws.onclose = () => { log('info', 'closed'); ws = null; document.getElementById('wssend').disabled = true; document.getElementById('wsconnect').textContent = 'Connect ws://localhost:8080/v1/testservice1' }
    }
    function wsSend() {
      const inp = document.getElementById('wsmsg')
      if (ws && inp.value) { ws.send(inp.value); log('msg', '→ ' + inp.value); inp.value = '' }
    }
    document.getElementById('wsmsg').addEventListener('keydown', e => { if (e.key === 'Enter') wsSend() })
  </script>
</body>
</html>`
