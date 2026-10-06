"""Manifeste d'exécution : de quoi rejouer une analyse et prouver sur quoi elle a porté.

- empreinte des exports analysés, prise avant et après l'exécution (les preuves n'ont pas bougé) ;
- version exacte du code (commits des deux dépôts, état du dépôt, versions des paquets) ;
- modèle et serveur d'inférence (build, arguments, image, fichier de modèle), paramètres de tirage ;
- empreinte des prompts et des livrables.
"""

import hashlib
import importlib.metadata
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ileapp_mcp

from forensic_harness import config, prompts
from forensic_harness.budget import _server

PACKAGES = ("forensic-harness", "ileapp-mcp", "langgraph", "langchain-core", "langchain-openai", "mcp")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def evidence_fingerprint(case: Path) -> dict[str, Any]:
    """Empreinte du dossier iLEAPP : chaque fichier, puis une empreinte d'ensemble.

    Couvre tout le dossier sauf la copie du système de fichiers de l'appareil (`data/`) et les
    médias extraits (`media/`) : exports TSV/CSV quelle que soit leur casse, métadonnées et bases
    iLEAPP, pages HTML. C'est un sur-ensemble de ce que le serveur MCP lit pour le harness.
    """
    files = sorted(
        p
        for p in case.rglob("*")
        if p.is_file() and not {"data", "media"} & set(p.relative_to(case).parts[:-1])
    )
    hashes = {p.relative_to(case).as_posix(): sha256_file(p) for p in files}
    tree = hashlib.sha256(
        "\n".join(f"{h}  {name}" for name, h in sorted(hashes.items())).encode()
    ).hexdigest()
    return {"files": len(hashes), "tree_sha256": tree, "per_file": hashes}


def code_state() -> dict[str, Any]:
    """Version du code qui tourne en ce moment."""
    return {"harness": _git(config.ROOT), "prompts_sha256": prompts.digest()}


def _git(repo: Path) -> dict[str, Any]:
    def run(*args: str) -> str | None:
        try:
            out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    status = run("status", "--porcelain")
    return {"commit": run("rev-parse", "HEAD"), "dirty": None if status is None else bool(status)}


def _inference() -> dict[str, Any]:
    """Ce que le serveur d'inférence dit de lui-même, et ce que Docker sait de son conteneur.

    Un serveur de lecture séparé est décrit de même sous `lecture`.
    """
    info = _describe(config.LLM_URL, config.MODEL, config.LLM_CONTAINER)
    if config.READ_LLM_URL:
        info["lecture"] = _describe(
            config.READ_LLM_URL, config.READ_MODEL or config.MODEL, config.READ_LLM_CONTAINER
        )
    return info


def _describe(url: str, model: str, container: str) -> dict[str, Any]:
    info: dict[str, Any] = {"url": url, "model": model}
    try:
        props = _server("/props", base=url)
        info.update(
            build=props.get("build_info"), model_path=props.get("model_path"), slots=props.get("total_slots")
        )
    except (OSError, ValueError) as e:
        info["unreachable"] = str(e)
    try:
        out = subprocess.run(
            ["docker", "inspect", container, "--format",
             "{{json .Image}}|{{json .Config.Image}}|{{json .Args}}|{{json .HostConfig.Binds}}"],
            capture_output=True, text=True, timeout=20,
        )  # fmt: skip
        if out.returncode == 0:
            image_id, image, args, binds = (json.loads(part) for part in out.stdout.strip().split("|"))
            info["container"] = {"image_id": image_id, "image": image, "args": args, "model_mounts": binds}
            # fichier du modèle côté hôte ; un blob Ollama porte son SHA-256 dans son nom
            info["model_file"] = next(
                (b.split(":")[0] for b in binds or [] if ".gguf" in b or "/blobs/" in b), None
            )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass  # pas de Docker sur cette machine : le manifeste le montre par l'absence de `container`
    return info


def start(case: Path) -> dict[str, Any]:
    """Partie du manifeste connue avant le premier appel au modèle."""
    versions = {}
    for name in PACKAGES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return {
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "case": str(case),
        "evidence": evidence_fingerprint(case),
        "code": {
            "harness": _git(config.ROOT),
            "ileapp_mcp": _git(Path(ileapp_mcp.__file__).resolve().parents[2]),
            "packages": versions,
            "python": platform.python_version(),
        },
        "inference": _inference(),
        "sampling": {"temperature": config.LLM_TEMPERATURE, "seed": config.LLM_SEED, "thinking": False},
        "prompts_sha256": prompts.digest(),
        "settings": {
            "chunk_tokens": config.CHUNK_TOKENS,
            "max_findings": config.MAX_FINDINGS,
            "max_field_chars": config.MAX_FIELD_CHARS,
            "max_scenarios": config.MAX_SCENARIOS,
            "instruction_rounds": config.INSTRUCTION_ROUNDS,
            "tool_rows": config.TOOL_ROWS,
            "counter_rounds": config.COUNTER_ROUNDS,
            "qualifications": str(config.QUALIFICATIONS),
            "llm_parallel": config.LLM_PARALLEL,
            "read_parallel": config.READ_PARALLEL if config.READ_LLM_URL else None,
            "llm_cache": config.LLM_CACHE or None,
        },
    }


def check_evidence(manifest: dict[str, Any], case: Path, stage: str) -> tuple[dict[str, Any], list[str]]:
    """Les preuves ont-elles bougé depuis le début de l'exécution ? Renvoie (manifeste complété, anomalies).

    Appelé juste après l'extraction (ce qui a été lu est-il ce qui a été empreinté ?) puis à la fin.
    Une modification défaite entre deux contrôles n'est pas visible ici ; l'empreinte de chaque
    ligne lue, elle, est dans extraction.json.
    """
    after = evidence_fingerprint(case)
    unchanged = after["tree_sha256"] == manifest["evidence"]["tree_sha256"]
    problems = []
    if not unchanged:
        before = manifest["evidence"]["per_file"]
        changed = sorted(
            n for n in set(before) | set(after["per_file"]) if before.get(n) != after["per_file"].get(n)
        )
        more = f" … et {len(changed) - 10} autres" if len(changed) > 10 else ""
        problems.append(
            f"LES PREUVES ONT CHANGÉ PENDANT L'EXÉCUTION ({stage}) : {', '.join(changed[:10])}{more}"
        )
    check = {
        "stage": stage,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tree_sha256": after["tree_sha256"],
        "unchanged": unchanged,
    }
    checks = [*manifest.get("evidence_checks", []), check]
    return {
        **manifest,
        "evidence_checks": checks,
        "evidence_unchanged": all(c["unchanged"] for c in checks),
        "evidence_after_tree_sha256": after["tree_sha256"],
    }, problems


def check_code(manifest: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Le code a-t-il changé entre le début de l'exécution et la production du rapport (reprise) ?"""
    now = code_state()
    then = {"harness": manifest["code"]["harness"], "prompts_sha256": manifest["prompts_sha256"]}
    problems = (
        []
        if now == then
        else ["le code ou les prompts ont changé entre l'analyse et la production du rapport"]
    )
    return {**manifest, "code_at_report": now}, problems


def _sealed(run_dir: Path) -> list[Path]:
    return [
        p
        for p in sorted(run_dir.rglob("*"))
        if p.is_file() and p.name not in ("manifest.json", "manifest.sha256")
    ]


def seal(run_dir: Path, manifest: dict[str, Any]) -> str:
    """Consigne l'empreinte de chaque fichier de l'exécution et fige le dossier.

    Renvoie l'empreinte du manifeste : c'est elle qu'il faut noter hors de la machine (procès-verbal,
    trace Langfuse) pour que toute modification ultérieure du dossier soit détectable par `verify`.
    """
    manifest = {
        **manifest,
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "outputs_sha256": {p.relative_to(run_dir).as_posix(): sha256_file(p) for p in _sealed(run_dir)},
    }
    path = run_dir / "manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    digest = sha256_file(path)
    (run_dir / "manifest.sha256").write_text(f"{digest}  manifest.json\n", encoding="utf-8")
    for p in sorted(run_dir.rglob("*"), reverse=True):
        p.chmod(0o555 if p.is_dir() else 0o444)
    run_dir.chmod(0o555)
    return digest


def verify(run_dir: Path, expected_manifest_sha256: str | None = None) -> list[str]:
    """Contrôle a posteriori d'une exécution figée. Renvoie la liste des écarts (vide si tout concorde)."""
    problems = []
    man_path = run_dir / "manifest.json"
    digest = sha256_file(man_path)
    recorded = (run_dir / "manifest.sha256").read_text(encoding="utf-8").split()[0]
    if digest != recorded:
        problems.append("manifest.json ne correspond plus à manifest.sha256")
    if expected_manifest_sha256 and not digest.startswith(expected_manifest_sha256.lower()):
        problems.append("l'empreinte du manifeste ne correspond pas à celle qui a été notée")
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    actual = {p.relative_to(run_dir).as_posix(): sha256_file(p) for p in _sealed(run_dir)}
    recorded_outputs = manifest.get("outputs_sha256", {})
    for name in sorted(set(actual) | set(recorded_outputs)):
        if actual.get(name) != recorded_outputs.get(name):
            state = (
                "ajouté" if name not in recorded_outputs else "supprimé" if name not in actual else "modifié"
            )
            problems.append(f"fichier {state} depuis la clôture : {name}")
    case = Path(manifest["case"])
    if not case.is_dir():
        problems.append(f"dossier de preuves introuvable, non revérifié : {case}")
    elif evidence_fingerprint(case)["tree_sha256"] != manifest["evidence"]["tree_sha256"]:
        problems.append("les preuves ne sont plus celles qui ont été analysées")
    return problems
