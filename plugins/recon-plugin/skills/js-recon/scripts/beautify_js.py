#!/usr/bin/env python3
import subprocess


def beautify_javascript(content: str, indent_size: int = 2, timeout: int = 30) -> tuple[str, bool]:
    try:
        import jsbeautifier

        opts = jsbeautifier.default_options()
        opts.indent_size = indent_size
        beautified = jsbeautifier.beautify(content, opts)
        if beautified.strip():
            return beautified, True
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["js-beautify", "--stdin", "--indent-size", str(indent_size)],
            input=content,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout, True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return content, False
