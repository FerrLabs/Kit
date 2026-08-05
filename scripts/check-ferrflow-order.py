#!/usr/bin/env python3
"""Vérifie que ferrflow.json publie chaque crate après ses dépendances internes.

FerrFlow publie dans l'ordre de déclaration du tableau `package` — le champ
`dependsOn` documente la relation mais ne réordonne rien. Une crate placée
avant une de ses dépendances échoue donc au `cargo publish`, parce que la
version attendue n'est pas encore au registre.

Ce n'est pas théorique : la release du 2026-08-05 s'est arrêtée sur
`ferrlabs-audit`, publié avant `ferrlabs-id` dont il dépend. Rien ne validait
l'ordre, et il ne se manifeste que lorsque deux crates liées bougent ensemble —
d'où un fichier resté faux sans que personne le voie.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def internal_deps(crate_dir: pathlib.Path) -> set[str]:
    """Les `ferrlabs-*` dont dépend cette crate, toutes sections confondues."""
    manifest = crate_dir / "Cargo.toml"
    if not manifest.is_file():
        return set()
    names = set(re.findall(r"^(ferrlabs-[a-z-]+)\s*=", manifest.read_text(), re.M))
    return names - {f"ferrlabs-{crate_dir.name}"}


def main() -> int:
    config = json.loads((ROOT / "ferrflow.json").read_text())
    order = [p["name"] for p in config["package"]]
    rank = {name: i for i, name in enumerate(order)}

    problems = []
    for crate_dir in sorted((ROOT / "crates").iterdir()):
        name = f"ferrlabs-{crate_dir.name}"
        if name not in rank:
            problems.append(f"{name} n'est pas déclaré dans ferrflow.json : il ne sera jamais publié")
            continue
        for dep in sorted(internal_deps(crate_dir)):
            if dep in rank and rank[dep] > rank[name]:
                problems.append(
                    f"{name} (position {rank[name]}) est publié avant {dep} (position {rank[dep]})"
                )

    if problems:
        print("ferrflow.json : ordre de publication invalide\n")
        for p in problems:
            print(f"  - {p}")
        print("\nDéplacez chaque dépendance avant la crate qui l'utilise dans le tableau `package`.")
        return 1

    print(f"ferrflow.json : {len(order)} packages, ordre de publication valide")
    return 0


if __name__ == "__main__":
    sys.exit(main())
