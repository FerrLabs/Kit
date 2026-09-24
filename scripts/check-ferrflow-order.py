#!/usr/bin/env python3
"""Check that ferrflow.json publishes every crate after its internal dependencies.

FerrFlow publishes in the declaration order of the `package` array: the
`dependsOn` field documents the relation but reorders nothing. A crate placed
before one of its dependencies therefore fails at `cargo publish`, because the
expected version is not on the registry yet.

This is not theoretical: the 2026-08-05 release stopped on `ferrlabs-audit`,
published before the `ferrlabs-id` it depends on. Nothing validated the order,
and it only shows up when two linked crates move together, which is how the
file stayed wrong without anyone seeing it.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def internal_deps(crate_dir: pathlib.Path) -> set[str]:
    """The `ferrlabs-*` this crate depends on, across every section."""
    manifest = crate_dir / "Cargo.toml"
    if not manifest.is_file():
        return set()
    # `[a-z0-9-]` and not `[a-z-]`: a name containing a digit would otherwise be
    # ignored silently, so the edge would go missing from the graph with nothing
    # to say so, exactly the kind of blind spot this script exists to close.
    names = set(re.findall(r"^(ferrlabs-[a-z0-9-]+)\s*=", manifest.read_text(), re.M))
    return names - {f"ferrlabs-{crate_dir.name}"}


def main() -> int:
    config = json.loads((ROOT / "ferrflow.json").read_text())
    order = [p["name"] for p in config["package"]]
    rank = {name: i for i, name in enumerate(order)}

    problems = []
    for crate_dir in sorted((ROOT / "crates").iterdir()):
        name = f"ferrlabs-{crate_dir.name}"
        if name not in rank:
            problems.append(f"{name} is not declared in ferrflow.json: it will never be published")
            continue
        for dep in sorted(internal_deps(crate_dir)):
            if dep in rank and rank[dep] > rank[name]:
                problems.append(
                    f"{name} (position {rank[name]}) is published before {dep} (position {rank[dep]})"
                )

    if problems:
        print("ferrflow.json: invalid publish order\n")
        for p in problems:
            print(f"  - {p}")
        print("\nMove each dependency before the crate that uses it in the `package` array.")
        return 1

    print(f"ferrflow.json: {len(order)} packages, publish order valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
