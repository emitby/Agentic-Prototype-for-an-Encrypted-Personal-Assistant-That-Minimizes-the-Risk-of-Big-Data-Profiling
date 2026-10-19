"""Grocery lists and consumable-supply tracking (e.g. laundry detergent).

Supply estimates are plain arithmetic over your own readings, so the model
reports numbers it didn't compute and can't get wrong.

How the estimate works:
- You log readings: a "restock" (bought more, amount now on hand) or a
  "level" (how much is left right now). Amounts use the supply's unit, e.g.
  loads or fl oz.
- Daily usage is learned from the drops between consecutive readings. A
  restock starts a new baseline. Until there are two readings, the configured
  usage (e.g. 4 loads a week at 1.5 oz) is used instead.
- Remaining now = last reading - daily usage x days since that reading.
"""

from datetime import date, timedelta


class HouseholdError(ValueError):
    pass


def _parse_date(value):
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise HouseholdError(f"Invalid date {value!r}; use YYYY-MM-DD.") from None


class Groceries:
    def __init__(self, vault):
        self.vault = vault

    @property
    def _lists(self):
        return self.vault.data["grocery_lists"]

    def _list(self, name, create=False):
        key = name.strip().lower()
        if key not in self._lists:
            if not create:
                known = ", ".join(sorted(self._lists)) or "none yet"
                raise HouseholdError(f"No grocery list named {name!r}. Lists: {known}.")
            self._lists[key] = []
        return self._lists[key]

    def show(self, list_name=None):
        if list_name:
            return {list_name.lower(): self._list(list_name)}
        return self._lists

    def add_items(self, list_name, items):
        lst = self._list(list_name, create=True)
        added = []
        for item in items:
            name = str(item.get("name", "")).strip()
            if not name:
                raise HouseholdError("Every item needs a name.")
            qty = str(item.get("qty") or "1")
            existing = next((i for i in lst if i["name"].lower() == name.lower() and not i["done"]), None)
            if existing:
                existing["qty"] = qty
            else:
                lst.append({"name": name, "qty": qty, "done": False})
            added.append(name)
        self.vault.save()
        return {"list": list_name.lower(), "added_or_updated": added, "items": lst}

    def check_off(self, list_name, item_names):
        lst = self._list(list_name)
        wanted = {n.lower() for n in item_names}
        hits = [i["name"] for i in lst if i["name"].lower() in wanted and not i["done"]]
        for i in lst:
            if i["name"].lower() in wanted:
                i["done"] = True
        self.vault.save()
        missing = sorted(wanted - {h.lower() for h in hits})
        return {"checked_off": hits, "not_found": missing}

    def remove_items(self, list_name, item_names):
        lst = self._list(list_name)
        wanted = {n.lower() for n in item_names}
        before = len(lst)
        lst[:] = [i for i in lst if i["name"].lower() not in wanted]
        self.vault.save()
        return {"removed": before - len(lst), "items": lst}

    def clear_done(self, list_name):
        lst = self._list(list_name)
        lst[:] = [i for i in lst if not i["done"]]
        self.vault.save()
        return {"items": lst}


class Supplies:
    def __init__(self, vault, today=date.today):
        self.vault = vault
        self.today = today

    @property
    def _supplies(self):
        return self.vault.data["supplies"]

    def _supply(self, name):
        key = name.strip().lower()
        if key not in self._supplies:
            known = ", ".join(sorted(self._supplies)) or "none yet"
            raise HouseholdError(f"Not tracking {name!r}. Tracked supplies: {known}.")
        return self._supplies[key]

    def track(self, name, unit, configured_daily_use=None, reorder_lead_days=5):
        """Start tracking a supply. configured_daily_use is used until readings exist."""
        if configured_daily_use is not None and configured_daily_use < 0:
            raise HouseholdError("Daily use can't be negative.")
        key = name.strip().lower()
        existing = self._supplies.get(key, {})
        self._supplies[key] = {
            "unit": unit, "configured_daily_use": configured_daily_use,
            "reorder_lead_days": reorder_lead_days, "readings": existing.get("readings", []),
        }
        self.vault.save()
        return self.estimate(key)

    def log(self, name, kind, amount, on=None):
        """kind: 'restock' (amount on hand after buying) or 'level' (amount left now)."""
        if kind not in ("restock", "level"):
            raise HouseholdError("kind must be 'restock' or 'level'.")
        if amount < 0:
            raise HouseholdError("Amount can't be negative.")
        supply = self._supply(name)
        day = _parse_date(on) or self.today()
        if day > self.today():
            raise HouseholdError("Readings can't be in the future.")
        supply["readings"].append({"date": day.isoformat(), "kind": kind, "amount": amount})
        supply["readings"].sort(key=lambda r: r["date"])
        self.vault.save()
        return self.estimate(name)

    def _learned_daily_use(self, readings):
        used, days = 0.0, 0
        for prev, cur in zip(readings, readings[1:]):
            span = (date.fromisoformat(cur["date"]) - date.fromisoformat(prev["date"])).days
            if cur["kind"] == "restock":
                continue   # a restock interval's drop is unknown; skip it
            drop = prev["amount"] - cur["amount"]
            if span > 0 and drop >= 0:
                used += drop
                days += span
        return (used / days) if days else None

    def estimate(self, name):
        key = name.strip().lower()
        supply = self._supply(key)
        readings = supply["readings"]
        learned = self._learned_daily_use(readings)
        rate = learned if learned is not None else supply["configured_daily_use"]
        result = {"supply": key, "unit": supply["unit"],
                  "daily_use": round(rate, 3) if rate is not None else None,
                  "daily_use_source": "learned from your readings" if learned is not None
                  else "configured" if rate is not None else "unknown"}
        if not readings:
            result["status"] = "No readings yet. Log how much you have."
            return result

        last = readings[-1]
        elapsed = (self.today() - date.fromisoformat(last["date"])).days
        if rate is None:
            result.update(remaining=last["amount"], status="Need a second reading or a configured daily use to estimate.")
            return result

        remaining = max(last["amount"] - rate * elapsed, 0.0)
        result["remaining"] = round(remaining, 2)
        result["as_of"] = self.today().isoformat()
        if rate == 0:
            result["status"] = "Not being used up."
            return result
        days_left = remaining / rate
        run_out = self.today() + timedelta(days=int(days_left))
        lead = supply["reorder_lead_days"]
        result.update(
            days_left=round(days_left, 1),
            runs_out_around=run_out.isoformat(),
            reorder_by=(run_out - timedelta(days=lead)).isoformat(),
            enough_for_next_week=days_left >= 7,
            status=("Out or nearly out. Buy now." if days_left < 1
                    else f"Reorder soon: under {lead} days left." if days_left <= lead
                    else "OK."),
        )
        return result

    def estimate_all(self):
        return [self.estimate(name) for name in sorted(self._supplies)]
