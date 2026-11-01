"""Requêtes JSON vers le relais, avec la bibliothèque standard uniquement."""
import json
import urllib.error
import urllib.request


class RelayError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _call(req, timeout):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("error", e.reason)
        except ValueError:
            detail = e.reason
        raise RelayError(detail, e.code) from None
    except (urllib.error.URLError, OSError) as e:
        raise RelayError(f"Relais injoignable ({getattr(e, 'reason', e)})") from None


def get_json(url, timeout=5):
    return _call(urllib.request.Request(url), timeout)


def post_json(url, data, timeout=5):
    req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return _call(req, timeout)
