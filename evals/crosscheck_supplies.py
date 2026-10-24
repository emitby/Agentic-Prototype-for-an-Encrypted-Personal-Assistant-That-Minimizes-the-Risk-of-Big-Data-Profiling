"""Independent supply-estimate cross-check: re-derive run-out estimates and compare.

The Household Agent reports supply numbers (days left, run-out date, reorder-by date)
but never computes them; ``assistant.household.Supplies.estimate`` does. If that code
were wrong, every answer would be wrong *consistently*. This module re-derives the same
numbers from the documented method (README, "How supply estimates work"), written again
from scratch, and compares them over many randomized reading histories. It imports
nothing from ``assistant.household`` except the class under test.

Documented method:

* Daily use is learned from the drop between consecutive readings. An interval that
  ends in a restock is skipped (its usage is unknown), as is one where the amount rose.
  Learned use = total drop / total days over the usable intervals.
* Until a usable interval exists, the configured daily use is used. With neither, the
  estimate reports the last reading as what's left and nothing more.
* remaining = max(last reading - daily use x days since it, 0)
* days left = remaining / daily use; run-out = today + whole days left;
  reorder by = run-out - lead days.

The histories are generated with a fixed seed (reproducible) and cover restocks, level
readings, gaps of different lengths, configured-only supplies, zero use and supplies
already used up.
"""

import random
from datetime import date, timedelta


def independent_estimate(readings, configured, lead_days, today):
    """Re-derive one supply's estimate from its readings, using only the documented method.

    Args:
        readings: ``[{"date": ISO, "kind": "restock"|"level", "amount": float}]`` sorted by date.
        configured: Configured daily use, or ``None``.
        lead_days: Reorder lead time in days.
        today: A ``datetime.date``.

    Returns:
        ``{"daily_use", "remaining", "days_left", "runs_out_around", "reorder_by"}``; fields
        that can't be computed are ``None``.
    """
    total_drop, total_days = 0.0, 0
    for i in range(1, len(readings)):
        before, after = readings[i - 1], readings[i]
        if after["kind"] == "restock":
            continue
        gap = (date.fromisoformat(after["date"]) - date.fromisoformat(before["date"])).days
        drop = before["amount"] - after["amount"]
        if gap > 0 and drop >= 0:
            total_drop += drop
            total_days += gap
    rate = total_drop / total_days if total_days else configured
    out = {"daily_use": None if rate is None else round(rate, 3), "remaining": None, "days_left": None,
           "runs_out_around": None, "reorder_by": None}
    if not readings:
        return out
    if rate is None:
        # One reading and no configured use: nothing to subtract yet, so what's left is the last reading.
        out["remaining"] = readings[-1]["amount"]
        return out
    since = (today - date.fromisoformat(readings[-1]["date"])).days
    remaining = max(readings[-1]["amount"] - rate * since, 0.0)
    out["remaining"] = round(remaining, 2)
    if rate > 0:
        left = remaining / rate
        run_out = today + timedelta(days=int(left))
        out.update(days_left=round(left, 1), runs_out_around=run_out.isoformat(),
                   reorder_by=(run_out - timedelta(days=lead_days)).isoformat())
    return out


def random_history(rng, today):
    """One randomized supply: readings over the last ~90 days, a configured rate and a lead time."""
    day = today - timedelta(days=rng.randint(30, 90))
    amount = rng.choice([32, 64, 100, 150])
    readings = [{"date": day.isoformat(), "kind": "restock", "amount": amount}]
    for _ in range(rng.randint(0, 6)):
        day += timedelta(days=rng.randint(1, 14))
        if day > today:
            break
        if rng.random() < 0.25:
            amount = rng.choice([32, 64, 100])
            readings.append({"date": day.isoformat(), "kind": "restock", "amount": amount})
        else:
            amount = max(round(amount - rng.uniform(0, 12), 1), 0)
            readings.append({"date": day.isoformat(), "kind": "level", "amount": amount})
    configured = rng.choice([None, 0.0, 0.5, 0.714, 2.0])
    return readings, configured, rng.choice([0, 3, 5, 10])


def crosscheck(supplies_factory, cases=400, seed=20261024, today=None):
    """Compare ``Supplies.estimate`` with :func:`independent_estimate` on random histories.

    Args:
        supplies_factory: ``today -> Supplies`` on a fresh vault (so the app's own code runs).
        cases: How many random supplies to check.
        seed: RNG seed (fixed, so failures are reproducible).
        today: The date to estimate on (default: today).

    Returns:
        ``{"checked", "fields_compared", "coverage": {branch: count}, "mismatches": [...], "ok"}``.
        ``ok`` also requires every branch of the method to have been exercised at least once.
    """
    today = today or date.today()
    rng = random.Random(seed)
    supplies = supplies_factory(lambda: today)
    mismatches, fields = [], 0
    coverage = {"learned rate": 0, "configured rate only": 0, "no rate": 0, "zero use": 0, "used up": 0}
    for i in range(cases):
        readings, configured, lead = random_history(rng, today)
        name = f"supply {i}"
        supplies.track(name, "units", configured_daily_use=configured, reorder_lead_days=lead)
        supplies._supplies[name]["readings"] = [dict(r) for r in readings]
        app = supplies.estimate(name)
        ours = independent_estimate(readings, configured, lead, today)
        # Which branches of the method this history exercised (reported, so the sample's reach is visible).
        source = app.get("daily_use_source", "")
        coverage["learned rate" if source.startswith("learned") else
                 "configured rate only" if source == "configured" else "no rate"] += 1
        coverage["zero use"] += ours["daily_use"] == 0
        coverage["used up"] += ours["remaining"] == 0
        for key, value in ours.items():
            fields += 1
            theirs = app.get(key)
            same = (theirs == value) if not isinstance(value, float) else theirs is not None and abs(theirs - value) < 1e-6
            if not same:
                mismatches.append({"case": i, "field": key, "app": theirs, "independent": value})
    return {"checked": cases, "fields_compared": fields, "coverage": coverage, "mismatches": mismatches,
            "ok": not mismatches and all(coverage.values())}
