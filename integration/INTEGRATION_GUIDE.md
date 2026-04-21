# HoneyTrap + Dummy Website Integration

## 1) HoneyTrap configuration

Set these variables in HoneyTrap `.env`:

```env
LOG_API_KEY=change_this_to_a_long_random_key
EXTERNAL_FAILED_LOGIN_THRESHOLD=5
EXTERNAL_FAILED_LOGIN_WINDOW_SEC=300
```

Start HoneyTrap:

```powershell
python run.py
```

## 2) Dummy website configuration

Set environment variables in your dummy Flask app:

```env
HONEYTRAP_API_URL=http://127.0.0.1:5000/api/logs
HONEYTRAP_API_KEY=change_this_to_a_long_random_key
DUMMY_SOURCE_NAME=dummy-site-1
HONEYTRAP_TIMEOUT_SEC=2
```

## 3) Plug middleware into dummy app

```python
from flask import Flask
from integration.dummy_site_middleware import register_honeytrap_logging

app = Flask(__name__)
register_honeytrap_logging(app)
```

The middleware captures request metadata and submits JSON logs to HoneyTrap.

## 4) Verify

1. Open dummy site and trigger a few requests (especially login failures).
2. Login to HoneyTrap.
3. Open `/logs` page. You should see external logs and alert highlights.

## 5) API contract

HoneyTrap expects `POST /api/logs` with header:

`X-API-KEY: <LOG_API_KEY>`

Body:

```json
{
  "source": "dummy-site-1",
  "ip": "192.168.1.1",
  "user_agent": "Mozilla/5.0 ...",
  "endpoint": "/login",
  "method": "POST",
  "status": "failed",
  "payload": "username=admin' OR '1'='1",
  "timestamp": "2026-04-19T12:00:00"
}
```
