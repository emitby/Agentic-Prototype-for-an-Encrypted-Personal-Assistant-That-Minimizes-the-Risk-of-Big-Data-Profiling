from types import SimpleNamespace as NS
from urllib.parse import unquote

import httpx
import pytest

from assistant.security import HIBPClient
from assistant.vault import Vault

PASSPHRASE = "correct horse battery staple"
FAST_N = 2 ** 14   # keep scrypt quick in tests


@pytest.fixture
def vault(tmp_path):
    return Vault.create(tmp_path / "vault.enc", PASSPHRASE, scrypt_n=FAST_N)


class FakeHIBP:
    """Mock HIBP server. `pwned` maps full uppercase SHA-1 -> count; `accounts` maps address -> breaches."""

    def __init__(self, pwned=None, accounts=None):
        self.pwned = pwned or {}
        self.accounts = accounts or {}
        self.requests = []

    def handler(self, request):
        self.requests.append(request)
        if request.url.host == "api.pwnedpasswords.com":
            prefix = request.url.path.rsplit("/", 1)[-1]
            lines = [f"{h[5:]}:{c}" for h, c in self.pwned.items() if h.startswith(prefix)]
            lines.append("0000000000000000000000000000000000A:0")   # padding row
            return httpx.Response(200, text="\r\n".join(lines))
        address = unquote(request.url.raw_path.decode().split("?")[0].rsplit("/", 1)[-1])
        if request.headers.get("hibp-api-key") != "good-key":
            return httpx.Response(401)
        breaches = self.accounts.get(address, [])
        return httpx.Response(200, json=breaches) if breaches else httpx.Response(404)

    def client(self, api_key=None):
        return HIBPClient(http=httpx.Client(transport=httpx.MockTransport(self.handler)), api_key=api_key)


@pytest.fixture
def fake_hibp():
    return FakeHIBP()


# ---- scripted Claude client -------------------------------------------------

def text(t):
    return NS(type="text", text=t)


def tool_use(id_, name, **input_):
    return NS(type="tool_use", id=id_, name=name, input=input_)


def response(*content, stop="end_turn"):
    return NS(content=list(content), stop_reason=stop)


class FakeClaude:
    """Scripted responses, either one shared queue or one queue per agent.

    Per-agent scripts are keyed by agent name ("Coordinator", "Security", "Travel",
    "Household"), which keeps tests deterministic when specialists run in parallel.
    """

    def __init__(self, *responses, by_agent=None):
        self.responses = list(responses)
        self.by_agent = {k: list(v) for k, v in (by_agent or {}).items()}
        self.requests = []
        self.beta = NS(messages=NS(create=self._create))

    @staticmethod
    def agent_of(request):
        system = request["system"]
        return system.split("You are the ", 1)[1].split(" ", 1)[0] if "You are the " in system else "Coordinator"

    def _create(self, **kwargs):
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})
        if self.by_agent:
            return self.by_agent[self.agent_of(kwargs)].pop(0)
        return self.responses.pop(0)

    def requests_for(self, agent):
        return [r for r in self.requests if self.agent_of(r) == agent]

    def everything_sent(self):
        """All text that left the machine for the model, flattened."""
        return repr([(r["system"], r["messages"]) for r in self.requests])
