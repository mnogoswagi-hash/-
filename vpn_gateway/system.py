from __future__ import annotations

import subprocess
from collections.abc import Sequence


class SystemCommandError(RuntimeError):
    """A privileged command failed. Command output is never exposed to API clients."""


class Runner:
    def run(self, args: Sequence[str], *, stdin: str | None = None, check: bool = True) -> str:
        try:
            result = subprocess.run(list(args), input=stdin, capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SystemCommandError(f"Unable to execute {args[0]}") from error
        if result.returncode and check:
            # Never log stdin, stdout, argv or stderr, which could contain keys.
            raise SystemCommandError(f"{args[0]} exited with status {result.returncode}")
        if result.returncode:
            return ""
        return result.stdout.strip()

    def succeeds(self, args: Sequence[str]) -> bool:
        try:
            self.run(args)
        except SystemCommandError:
            return False
        return True
