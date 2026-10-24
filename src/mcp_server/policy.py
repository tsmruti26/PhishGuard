import collections
import json
import time
from pathlib import Path


class PolicyDenied(Exception):
    """Raised when a request is not allowed by the policy."""


class PolicyEngine:
    def __init__(self, policy_path):
        self.policy = json.loads(Path(policy_path).read_text(encoding="utf-8-sig"))
        self._calls = collections.defaultdict(collections.deque)

    def role(self, name):
        roles = self.policy.get("roles", {})
        if name not in roles:  # default deny
            raise PolicyDenied("unknown role")
        return roles[name]

    def authorize_tool(self, role_name, tool):
        role = self.role(role_name)
        if tool not in role.get("tools", []):
            raise PolicyDenied(f"tool '{tool}' is not permitted for this role")
        self._rate_limit(role_name, int(role.get("rate_limit_per_minute", 10)))
        return role

    def _rate_limit(self, role_name, limit):
        now = time.monotonic()
        window = self._calls[role_name]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            raise PolicyDenied("rate limit exceeded")
        window.append(now)

    def _table_rules(self, role, table):
        rules = role.get("tables", {}).get(table)
        if not rules:
            raise PolicyDenied(f"no access to table '{table}'")
        return rules

    def allowed_columns(self, role, table, requested=None):
        """Also used for filter columns, so a role cannot probe data it cannot read."""
        allowed = self._table_rules(role, table)["columns"]
        if requested is None:
            return list(allowed)
        denied = [c for c in requested if c not in allowed]
        if denied:
            raise PolicyDenied(f"column(s) not permitted: {', '.join(denied)}")
        return list(requested)

    def max_rows(self, role, table, requested):
        cap = int(self._table_rules(role, table).get("max_rows", 20))
        return max(1, min(int(requested), cap))

    def check_write(self, role, table):
        if table not in role.get("write_tables", []):
            raise PolicyDenied(f"write access to '{table}' is not permitted")

    def check_transition(self, role, current, new):
        if new not in role.get("status_transitions", {}).get(current, []):
            raise PolicyDenied(f"status change {current} -> {new} is not permitted")