"""Build and replay the sample coverage example for demo.sh."""

from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
CLI = [sys.executable, str(ROOT / "incident_to_promtool.py")]


def export_example(example, destination):
    # Reserve the new directory before publishing any files. A competing run
    # must leave its contents to the process that created it.
    with ExitStack() as rollback:
        destination.mkdir()
        rollback.callback(destination.rmdir)
        for name in ("complete.zip", "sparse.zip", "coverage.policy.json", "candidate.rules.yml",
                     "review.md", "review.json", "review.xml"):
            source = example / name
            target = destination / name
            with source.open("rb") as original, target.open("xb") as output:
                rollback.callback(target.unlink)
                shutil.copyfileobj(original, output)
        rollback.pop_all()


def run_demo(scratch, promtool, destination):
    example = scratch / "example"
    example.mkdir()
    matrix_path = DEMO / "incident.matrix.json"
    matrix = json.loads(matrix_path.read_bytes())
    series, = matrix["data"]["result"]
    # Drop the third scrape, one minute into the payment incident replay.
    del series["values"][2]
    sparse_path = scratch / "sparse.matrix.json"
    sparse_path.write_text(json.dumps(matrix), encoding="utf-8")

    shutil.copyfile(DEMO / "coverage.policy.json", example / "coverage.policy.json")
    shutil.copyfile(DEMO / "after.rules.yml", example / "candidate.rules.yml")
    for name, source in (("complete.zip", matrix_path), ("sparse.zip", sparse_path)):
        subprocess.run(
            [*CLI, "bundle", DEMO / "demo.json", "--matrix", source, "--rule-file", DEMO / "before.rules.yml",
             "--output", name],
            cwd=example, stdout=sys.stderr, check=True,
        )
    command = [
        *CLI, "compare-bundle", "complete.zip", "sparse.zip", "--after", "candidate.rules.yml",
        "--bundle-coverage-policy", "coverage.policy.json", "--promtool", promtool,
        "--json-report", "review.json", "--junit-report", "review.xml",
    ]
    markdown = example / "review.md"
    with markdown.open("wb") as output:
        comparison = subprocess.run(command, cwd=example, stdout=output)
    if comparison.returncode != 1:
        if comparison.returncode:
            comparison.check_returncode()
        raise ValueError("Expected the missing scrape to fail the sparse bundle's coverage check.")

    report = json.loads((example / "review.json").read_bytes())
    checks = report["bundle_coverage"]["checks"]
    gap_results = [(check["path"], (check["coverage"]["gate"] or {}).get("passed")) for check in checks]
    metrics_passed = all(check["coverage"].get("required_metrics", {}).get("passed") is True for check in checks)
    if (report["summary"]["after"] != {"matched": 4, "total": 4} or not metrics_passed
            or gap_results != [("complete.zip", True), ("sparse.zip", False)]):
        raise ValueError("Expected four matched checkpoints and only the sparse bundle's gap check to fail.")
    if destination is not None:
        export_example(example, destination)
        print(f"Saved replay inputs and reports to {destination}.", file=sys.stderr)
    sys.stdout.buffer.write(markdown.read_bytes())


if __name__ == "__main__":
    try:
        with TemporaryDirectory() as temporary:
            run_demo(Path(temporary), sys.argv[1], Path(sys.argv[2]) if sys.argv[2] else None)
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Coverage demo failed: {exc}", file=sys.stderr)
        sys.exit(2)
