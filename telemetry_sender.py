"""Envío no bloqueante de telemetría por HTTP o UDP con métricas y reintentos."""

import json
import os
import re
import socket
import threading
import time
from collections import deque
from urllib import request, parse


class TelemetrySender:
    """Emisor thread-safe configurable en tiempo de ejecución.

    max_attempts incluye el envío inicial. El máximo permitido es 1000.
    """

    MAX_ATTEMPTS_LIMIT = 1000

    def __init__(self, http_url=None, http_method=None, udp_host=None, udp_port=None,
                 bssid=None,
                 queue_size=1000, timeout=2.0, max_attempts=None,
                 max_retries=None, retry_base_delay=None,
                 retry_max_delay=None):
        self._lock = threading.RLock()
        self.http_url = http_url or os.getenv("TELEMETRY_URL")
        self.http_method = (http_method or os.getenv("TELEMETRY_METHOD", "POST")).upper()
        if self.http_method not in ("GET", "POST"):
            raise ValueError("http_method debe ser GET o POST")
        self.udp_host = udp_host or os.getenv("TELEMETRY_UDP_HOST")
        self.udp_port = int(udp_port or os.getenv("TELEMETRY_UDP_PORT", "9999"))
        self.bssid = self._validate_bssid(
            bssid if bssid is not None else os.getenv("TELEMETRY_BSSID")
        )
        self.timeout = float(timeout)

        if max_attempts is None:
            env_value = os.getenv("TELEMETRY_MAX_ATTEMPTS")
            if env_value is not None:
                max_attempts = int(env_value)
            elif max_retries is not None:
                max_attempts = int(max_retries) + 1
            else:
                max_attempts = self.MAX_ATTEMPTS_LIMIT
        self.max_attempts = self._validate_attempts(max_attempts)
        self.retry_base_delay = float(
            retry_base_delay if retry_base_delay is not None
            else os.getenv("TELEMETRY_RETRY_BASE_DELAY", "0.5")
        )
        self.retry_max_delay = float(
            retry_max_delay if retry_max_delay is not None
            else os.getenv("TELEMETRY_RETRY_MAX_DELAY", "10")
        )
        if self.retry_base_delay < 0 or self.retry_max_delay < 0:
            raise ValueError("Los delays no pueden ser negativos")

        self.queue = deque(maxlen=queue_size)
        self.condition = threading.Condition()
        self.running = True
        self.stats = {
            "started_at": time.time(),
            "messages_queued": 0,
            "messages_sent": 0,
            "messages_failed": 0,
            "attempts_total": 0,
            "retries_total": 0,
            "last_attempts": 0,
            "last_error": None,
            "last_success": None,
            "last_failure": None,
            "last_message_type": None,
            "queue_dropped": 0,
        }
        self.worker = threading.Thread(target=self._worker,
                                       name="telemetry-sender", daemon=True)
        self.worker.start()

    @classmethod
    def _validate_attempts(cls, value):
        value = int(value)
        if not 1 <= value <= cls.MAX_ATTEMPTS_LIMIT:
            raise ValueError("max_attempts debe estar entre 1 y 1000")
        return value

    @staticmethod
    def _validate_bssid(value):
        if value is None or str(value).strip() == "":
            return None
        normalized = str(value).strip().lower().replace("-", ":")
        if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", normalized):
            raise ValueError("bssid debe tener formato AA:BB:CC:DD:EE:FF")
        return normalized

    def configure(self, http_url=None, http_method=None, udp_host=None, udp_port=None,
                  bssid=None,
                  max_attempts=None, retry_base_delay=None,
                  retry_max_delay=None):
        """Actualiza destinos y política sin reiniciar el proceso."""
        with self._lock:
            if http_url is not None:
                self.http_url = http_url.strip() or None
            if http_method is not None:
                http_method = http_method.strip().upper()
                if http_method not in ("GET", "POST"):
                    raise ValueError("http_method debe ser GET o POST")
                self.http_method = http_method
            if udp_host is not None:
                self.udp_host = udp_host.strip() or None
            if udp_port is not None:
                self.udp_port = int(udp_port)
            if bssid is not None:
                self.bssid = self._validate_bssid(bssid)
            if max_attempts is not None:
                self.max_attempts = self._validate_attempts(max_attempts)
            if retry_base_delay is not None:
                self.retry_base_delay = max(0.0, float(retry_base_delay))
            if retry_max_delay is not None:
                self.retry_max_delay = max(0.0, float(retry_max_delay))

    def send(self, payload):
        message = dict(payload)
        message.setdefault("timestamp", time.time())
        with self._lock:
            if self.bssid:
                message.setdefault("bssid", self.bssid)
        encoded = json.dumps(message, ensure_ascii=False,
                             default=self._json_default)
        with self.condition:
            before = len(self.queue)
            self.queue.append(encoded)
            if before == self.queue.maxlen:
                self.stats["queue_dropped"] += 1
            self.stats["messages_queued"] += 1
            self.condition.notify()

    def metrics(self):
        with self._lock:
            result = dict(self.stats)
            result.update({
                "queue_size": len(self.queue),
                "running": self.running,
                "http_url": self.http_url,
                "http_method": self.http_method,
                "udp_host": self.udp_host,
                "udp_port": self.udp_port,
                "bssid": self.bssid,
                "max_attempts": self.max_attempts,
                "retry_base_delay": self.retry_base_delay,
                "retry_max_delay": self.retry_max_delay,
            })
            return result

    def close(self):
        self.running = False
        with self.condition:
            self.condition.notify_all()
        self.worker.join(timeout=self.timeout + self.retry_max_delay + 1.0)

    @staticmethod
    def _json_default(value):
        if hasattr(value, "item"):
            return value.item()
        if hasattr(value, "tolist"):
            return value.tolist()
        return str(value)

    def _worker(self):
        while self.running or self.queue:
            with self.condition:
                while not self.queue and self.running:
                    self.condition.wait(timeout=0.5)
                if not self.queue:
                    continue
                message = self.queue.popleft()
            self._deliver_with_retry(message)

    def _deliver_with_retry(self, message):
        with self._lock:
            http_url = self.http_url
            http_method = self.http_method
            udp_host, udp_port = self.udp_host, self.udp_port
            max_attempts = self.max_attempts
            base_delay, max_delay = self.retry_base_delay, self.retry_max_delay

        # Si no hay destino, se registra como fallo sin crear una espera inútil.
        if not http_url and not udp_host:
            self._record_failure(0, "No hay destino HTTP ni UDP configurado")
            return

        for attempt in range(1, max_attempts + 1):
            errors = []
            if http_url:
                try:
                    self._send_http(http_url, http_method, message, self.timeout)
                except Exception as exc:
                    errors.append("HTTP: {}".format(exc))
            if udp_host:
                try:
                    self._send_udp(udp_host, udp_port, message)
                except Exception as exc:
                    errors.append("UDP: {}".format(exc))

            with self._lock:
                self.stats["attempts_total"] += 1
                self.stats["last_attempts"] = attempt

            if not errors:
                with self._lock:
                    self.stats["messages_sent"] += 1
                    self.stats["last_success"] = time.time()
                return

            with self._lock:
                self.stats["last_error"] = "; ".join(errors)
                if attempt < max_attempts:
                    self.stats["retries_total"] += 1

            if attempt < max_attempts:
                delay = min(max_delay, base_delay * (2 ** min(attempt - 1, 30)))
                if attempt <= 3 or attempt % 100 == 0:
                    print("telemetry retry {}/{} en {:.2f}s: {}".format(
                        attempt, max_attempts, delay, "; ".join(errors)))
                time.sleep(delay)
            else:
                self._record_failure(attempt, "; ".join(errors))

    def _record_failure(self, attempts, error):
        with self._lock:
            self.stats["messages_failed"] += 1
            self.stats["last_attempts"] = attempts
            self.stats["last_error"] = error
            self.stats["last_failure"] = time.time()
        print("telemetry descartada tras {} intentos: {}".format(attempts, error))

    @staticmethod
    def _send_http(url, method, message, timeout=2.0):
        if method == "GET":
            separator = "&" if "?" in url else "?"
            target = url + separator + parse.urlencode({"data": message})
            req = request.Request(target, method="GET")
        else:
            body = message.encode("utf-8")
            req = request.Request(url, data=body, headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            }, method="POST")
        with request.urlopen(req, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError("HTTP status {}".format(response.status))
            response.read(1)

    @staticmethod
    def _send_udp(host, port, message, timeout=2.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(message.encode("utf-8"), (host, port))
        finally:
            sock.close()
