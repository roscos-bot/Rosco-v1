"""Rosco's Second Brain.

Built top-down, as Ross asked: the log first, then who may do what, then who
exists. Everything above this line is projection - there is exactly one source
of truth in the system and it is the append-only log in store.py.

    store.py    the log. Hash-chained, per node, replayed into everything else.
    vault.py    what agents learn, and the credentials they hold.
    grants.py   who may do what, and the four things that can happen.
    roster.py   who exists, what they command, what they answer to.
"""

__version__ = "0.1.0"
