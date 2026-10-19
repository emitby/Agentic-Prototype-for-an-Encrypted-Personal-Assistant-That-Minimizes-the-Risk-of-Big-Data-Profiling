from datetime import date

import pytest

from assistant.household import Groceries, HouseholdError, Supplies


class Today:
    def __init__(self, d):
        self.d = d

    def __call__(self):
        return self.d


def test_grocery_list_lifecycle(vault):
    g = Groceries(vault)
    g.add_items("Groceries", [{"name": "Eggs", "qty": "12"}, {"name": "Milk"}])
    g.add_items("groceries", [{"name": "eggs", "qty": "18"}])            # updates, no duplicate
    assert [(i["name"], i["qty"]) for i in g.show("groceries")["groceries"]] == [("Eggs", "18"), ("Milk", "1")]

    result = g.check_off("groceries", ["milk", "bread"])
    assert result == {"checked_off": ["Milk"], "not_found": ["bread"]}
    assert [i["name"] for i in g.clear_done("groceries")["items"]] == ["Eggs"]
    with pytest.raises(HouseholdError, match="No grocery list"):
        g.show("hardware")


def test_detergent_estimate_from_configured_usage(vault):
    today = Today(date(2026, 3, 10))
    s = Supplies(vault, today=today)
    s.track("Laundry detergent", "loads", configured_daily_use=0.5, reorder_lead_days=5)
    est = s.log("laundry detergent", "restock", 40)
    assert est["daily_use_source"] == "configured"
    assert est["days_left"] == 80 and est["runs_out_around"] == "2026-05-29"

    today.d = date(2026, 3, 30)          # 20 days later, no new readings
    est = s.estimate("laundry detergent")
    assert est["remaining"] == 30 and est["days_left"] == 60


def test_detergent_learns_usage_and_ignores_restock_jumps(vault):
    today = Today(date(2026, 4, 1))
    s = Supplies(vault, today=today)
    s.track("detergent", "fl oz", configured_daily_use=5)
    s.log("detergent", "restock", 100, on="2026-03-01")
    s.log("detergent", "level", 70, on="2026-03-11")     # 30 oz over 10 days
    s.log("detergent", "restock", 150, on="2026-03-15")  # interval skipped
    est = s.log("detergent", "level", 120, on="2026-03-25")  # 30 oz over 10 days
    assert est["daily_use"] == 3 and est["daily_use_source"] == "learned from your readings"
    # 7 days since last reading: 120 - 21 = 99 left, 33 days
    assert est["remaining"] == 99 and est["days_left"] == 33
    assert est["enough_for_next_week"] is True


def test_low_supply_flags_reorder(vault):
    s = Supplies(vault, today=Today(date(2026, 3, 10)))
    s.track("detergent", "loads", configured_daily_use=1, reorder_lead_days=5)
    est = s.log("detergent", "level", 3)
    assert est["status"].startswith("Reorder soon") and est["enough_for_next_week"] is False
    est = s.log("detergent", "level", 0.5)
    assert est["status"].startswith("Out or nearly out")


def test_supply_validation(vault):
    s = Supplies(vault, today=Today(date(2026, 3, 10)))
    with pytest.raises(HouseholdError, match="Not tracking"):
        s.log("soap", "level", 1)
    s.track("soap", "bars")
    with pytest.raises(HouseholdError, match="future"):
        s.log("soap", "level", 1, on="2026-04-01")
    with pytest.raises(HouseholdError, match="kind"):
        s.log("soap", "used", 1)
    assert "second reading" in s.log("soap", "level", 4)["status"]
