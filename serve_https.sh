#!/bin/bash
cd "$(dirname "$0")"

# Check if ngrok is available
if command -v ngrok &> /dev/null; then
    echo "Starting HTTP server + ngrok tunnel..."

    # Start Python HTTP server in background
    python3 -m http.server 8080 &
    PY_PID=$!

    sleep 1

    echo ""
    echo "==================================="
    echo "Starting ngrok tunnel..."
    echo "Look for the https://xxxx.ngrok.io URL"
    echo "==================================="
    echo ""

    # Run ngrok (will show the public URL)
    ngrok http 8080

    # Cleanup on exit
    kill $PY_PID 2>/dev/null
else
    echo "ngrok not found. Install it:"
    echo ""
    echo "  # Arch/Manjaro:"
    echo "  yay -S ngrok"
    echo ""
    echo "  # Or download from https://ngrok.com/download"
    echo ""
    echo "Falling back to local HTTPS server..."
    echo ""

    # Generate self-signed certificate if not exists
    if [ ! -f server.pem ]; then
        echo "Generating self-signed certificate..."
        openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes \
            -subj "/CN=192.168.0.15"
    fi

    echo ""
    echo "==================================="
    echo "HTTPS Server starting..."
    echo "Open on your device:"
    echo "  https://192.168.0.15:8443/benchmark.html"
    echo ""
    echo "Accept the security warning in browser"
    echo "==================================="
    echo ""

    python3 << 'EOF'
import http.server
import ssl

server_address = ('0.0.0.0', 8443)
handler = http.server.SimpleHTTPRequestHandler

httpd = http.server.HTTPServer(server_address, handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Server running... Press Ctrl+C to stop")
httpd.serve_forever()
EOF
fi
