# Example session

This is a real run against `claude-opus-5-5` and the live Have I Been Pwned API (October 2026). It used a throwaway vault with **test credentials only**, and has been lightly trimmed.

## Setup (CLI, secrets entered locally)

```
you> /add-email personal
  Email address: smoke.test@example.com
you> /add-login github          # site github.com, user smokeuser, password "password123" (deliberately weak)
you> /add-login bank            # site mybank.example, strong random password
```

## Request

```
you> Check my passwords for breaches. Also I have about 40 loads of laundry detergent left and do
     about 4 loads a week, how long will it last? And find me flights from JFK to Lisbon around
     May 14-21 next year. My github password is password123 by the way.
  (privacy filter removed before sending: [password:github])
```

The pasted password never reached the model. What Claude received ended in *"My github password is [password:github] by the way."*

## Agent activity

| Agent | Steps |
|---|---|
| Coordinator | Delegated to all three specialists **in parallel** |
| Security Agent | `list_accounts` → `check_password_breaches` → `check_email_breaches` (no HIBP key, so it got an error result and reported it) |
| Household Agent | `track_supply` (4 loads/week = 0.571/day) → `log_supply_reading` (40 loads) |
| Travel Agent | 6 web searches with server-side filtering |

Total time was about 55 seconds.

## Reply (trimmed)

> **What to do**
> 1. **Change your GitHub password now.** It has shown up in known data breaches over 2.2 million times and it's too short, so treat it as compromised. Turn on two-factor authentication. I can make a strong new password for you, but you'll need to change it on GitHub's site yourself. After that, run `/rotated github`.
> 2. **Set up email breach checks** by running `/set-hibp-key`.
> 3. **Buy laundry detergent by December 21.**
>
> **Password check**
> - **GitHub:** breached and weak. Change it now.
> - **Bank:** no breaches, not weak and not used anywhere else. Turn on two-factor authentication if your bank offers it.
> - Please don't paste passwords into the chat. The one you sent was hidden automatically before I saw it.
>
> **Laundry detergent**
> 40 loads at 4 a week lasts about 10 weeks, so you'll run out around **Monday, December 28**. Buying by December 21 gives you a week to spare.
>
> **Flights from JFK to Lisbon, May 2027**
> - **Aer Lingus, 1 stop in Dublin, May 15–23: from $710.40 round trip in economy.** The price may not include bags.
> - **Nonstops (TAP, JetBlue):** there are no May prices yet. They cost about $613–$650 round trip in winter.
> - **Possibly cheaper:** Azores Airlines, with 1 stop in Ponta Delgada.

## Checks

| Claim | Verified |
|---|---|
| Breach count | The live Pwned Passwords API returned 2.2M+ occurrences for the test password. Only the 5-character prefix `CBFDA` was sent. |
| Detergent math | 40 ÷ (4/7) = 70 days from Oct 19 = **Dec 28**, computed in `household.py`. The "buy by Dec 21" advice is a week before run-out. The default 5-day lead time would give Dec 23, so either the agent set a 7-day lead time or it added its own margin. The trace didn't record tool arguments, so this one date isn't verified. |
| Nothing readable on disk | After the run, the vault was scanned for `password123`, `smoke.test`, `detergent` and `Lisbon`, and **none were found**. |

## A fix this run prompted

The Travel Agent hit its search cap (6) before covering every option. The cap is now 10.
