"""`python -m rosco` is the console. There is no other entry point on purpose."""
from .console import main

raise SystemExit(main())
