#!/usr/bin/env python3
"""What .github/workflows/bench.yml runs: for each format, the sets to fetch and
the commands, and the machines it runs on. Prints the job matrix as JSON, for the
formats and machines asked for, comma-separated, or all of them.

zip and 7z compare with C programs that scripts/testdata.py builds, with MinGW's
compiler on Windows.
"""

import json
import sys

SILESIA = "target/testdata/silesia"
LINUX = "ubuntu-latest"
WINDOWS = "windows-latest"
MACOS = "macos-latest"
ALL = [LINUX, WINDOWS, MACOS]

FORMATS = {
    "tar": {"sets": ["silesia", "tar-bench-go"], "go": True, "machines": ALL,
            "package": "tar-bench", "runs": [""]},
    "age": {"sets": ["silesia", "age-bench-go"], "go": True, "machines": ALL,
            "package": "age-bench", "runs": [""]},
    "deflate": {"sets": ["silesia"], "go": False, "machines": ALL, "package": "deflate-bench",
                "runs": [f"--levels 1,6,9 {SILESIA}", f"--levels 1,6,9 --stream {SILESIA}",
                         f"--levels 1,6,9 --compress {SILESIA}"]},
    "bzip2": {"sets": ["silesia"], "go": False, "machines": ALL, "package": "bzip2-bench",
              "runs": [f"--levels 9 {SILESIA}", f"--levels 1,9 --compress {SILESIA}"]},
    "lz4": {"sets": ["silesia"], "go": False, "machines": ALL, "package": "lz4-bench",
            "runs": [f"--levels 1,9 {SILESIA}", f"--levels 1,9 --frame {SILESIA}",
                     f"--levels 1,9 --compress {SILESIA}"]},
    "xz": {"sets": ["silesia"], "go": False, "machines": ALL, "package": "xz-bench",
           "runs": [f"--presets 0,6 {SILESIA}", f"--presets 0,6 --compress {SILESIA}"]},
    "zstd": {"sets": ["silesia"], "go": False, "machines": ALL, "package": "zstd-bench",
             "runs": [f"--levels 1,3,9,19 {SILESIA}"]},
    "zip": {"sets": ["silesia", "zip-bench-libzip"], "go": False, "machines": ALL,
            "package": "zip-bench", "runs": [""]},
    "7z": {"sets": ["silesia", "7zz", "7z-bench-sdk"], "go": False, "machines": ALL,
           "package": "sevenz-bench", "runs": [""]},
}


def main() -> None:
    def wanted(arg: int, every: list) -> list:
        text = sys.argv[arg].strip() if len(sys.argv) > arg else ""
        if not text or text == "all":
            return every
        names = [name.strip() for name in text.split(",")]
        unknown = [name for name in names if name not in every]
        if unknown:
            sys.exit(f"unknown: {', '.join(unknown)}")
        return names

    machines = wanted(2, ALL)
    jobs = []
    for name in wanted(1, list(FORMATS)):
        plan = FORMATS[name]
        for machine in plan["machines"]:
            if machine in machines:
                jobs.append({"format": name, "os": machine, "package": plan["package"],
                             "go": plan["go"], "sets": " ".join(f"--set {s}" for s in plan["sets"]),
                             "runs": json.dumps(plan["runs"])})
    print(json.dumps({"include": jobs}))


if __name__ == "__main__":
    main()
