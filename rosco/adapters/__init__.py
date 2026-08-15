"""Adapters turn the outside world into Arrivals, and nothing more.

An adapter is a door, not a decision-maker. It takes whatever a channel hands it
- a Telegram update, an email, a phone transcript - resolves it into an
`arrive.Arrival`, and passes it to the Doorway. What comes back it relays.

The rule that bounds every adapter: IT MAY CARRY A QUESTION IN AND AN ANSWER
OUT, AND IT MAY CHANGE NOTHING. Raising an ask is fine - that is a question
waiting for Ross, written as a node fact anybody is allowed to write. Answering
one, granting anything, enrolling anybody, storing a secret: none of that is an
adapter's to do. Those need Ross's signature, which lives at the console, and an
adapter never holds it on the strength of an inbound message. This is the "only
localhost changes anything" rule from V6, applied at the edge.
"""
