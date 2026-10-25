"""HTTP session per connector: proxy, retries, User-Agent, rate limiting."""

import logging
import time
from collections import deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)


class RateLimiter:
    """
    Sliding-window limiter, e.g. Cisco openVuln: 5 calls/s, 30/min, 5000/day.
    `delay` is a minimum pause between two calls (polite scraping).
    """

    WINDOWS = {"per_second": 1, "per_minute": 60, "per_day": 86400}

    def __init__(self, limits=None, delay=0.0, clock=time.monotonic, sleep=time.sleep):
        self.limits = [(self.WINDOWS[k], int(v)) for k, v in (limits or {}).items()
                       if k in self.WINDOWS and v]
        self.delay = float(delay or 0)
        self.calls = deque()
        self.clock = clock
        self.sleep = sleep

    def wait(self):
        now = self.clock()
        if self.delay and self.calls and now - self.calls[-1] < self.delay:
            self.sleep(self.delay - (now - self.calls[-1]))
            now = self.clock()
        for window, limit in sorted(self.limits):
            while True:
                recent = [t for t in self.calls if now - t < window]
                if len(recent) < limit:
                    break
                pause = window - (now - recent[0])
                log.info("Rate limit (%d calls / %ds): waiting %.1fs", limit, window, pause)
                self.sleep(pause)
                now = self.clock()
        self.calls.append(now)
        longest = max([w for w, _ in self.limits] + [self.delay, 1])
        while self.calls and now - self.calls[0] >= longest:
            self.calls.popleft()


def proxies_from(proxy):
    """requests' proxies dict from a config "proxy" block (empty values ignored)."""
    return {k: v for k, v in (proxy or {}).items() if k in ("http", "https", "no_proxy") and v}


class HttpClient:
    def __init__(self, conn_config):
        http = conn_config.get("http", {})
        self.timeout = http.get("timeout", 30)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = http.get("user_agent", "advisory_cpe_generator")
        retry = Retry(total=int(http.get("retries", 3)), backoff_factor=1,
                      status_forcelist=(429, 500, 502, 503, 504), allowed_methods=None)
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        proxies = proxies_from(conn_config.get("proxy"))
        if proxies:
            self.session.proxies.update(proxies)
            log.info("Using proxy %s", {k: v for k, v in proxies.items() if k != "no_proxy"})
        self.limiter = RateLimiter(conn_config.get("rate_limit"), conn_config.get("delay", 0))

    def request(self, method, url, **kwargs):
        self.limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def get_json(self, url, **kwargs):
        return self.get(url, **kwargs).json()
