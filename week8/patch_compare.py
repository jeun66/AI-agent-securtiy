"""Compare independently recorded adaptive reports; never generate fake results."""
import argparse
import json
from pathlib import Path


def compare(before, after):
    if before.get("schema") != "w8-adaptive-before-v1" or after.get("schema") != "w8-adaptive-after-v1":
        raise ValueError("incorrect_measurement_phases")
    for key in ("baseline_commit", "mode", "budget_per_original_task", "seed"):
        if before.get(key) != after.get(key):
            raise ValueError("incomparable_" + key)
    b = {row["task_id"]: row for row in before["tasks"]}
    a = {row["task_id"]: row for row in after["tasks"]}
    if len(b) != len(before["tasks"]) or len(a) != len(after["tasks"]) or set(b) != set(a):
        raise ValueError("incomparable_task_set")
    for key in ("w7", "taint_provenance"):
        if before[key]["original_tasks"] != after[key]["original_tasks"]:
            raise ValueError("incomparable_denominator")
    details = []
    for name in sorted(b):
        left, right = b[name], a[name]
        for row in (left, right):
            if row["success"] != any(t["goal_reached"] for t in row["trials"]):
                raise ValueError("unsupported_attack_success")
            if not 1 <= row["attempts_used"] <= before["budget_per_original_task"]:
                raise ValueError("invalid_search_budget")
        details.append({"task": name, "before": left["success"], "after": right["success"],
                        "tries_before": left["attempts_used"], "tries_after": right["attempts_used"]})
    def metric(name):
        b_row, a_row = before[name], after[name]
        return {"before": b_row["asr"], "after": a_row["asr"],
                "delta": a_row["asr"] - b_row["asr"], "n": a_row["original_tasks"]}
    return {
        "schema": "w8-paired-patch-v1", "mode": before["mode"], "seed": before["seed"],
        "budget_per_task": before["budget_per_original_task"],
        "w7": metric("w7"), "taint_provenance": metric("taint_provenance"),
        "utility": {"before": before["utility"], "after": after["utility"]},
        "fpr": {"before": before["fpr"], "after": after["fpr"]},
        "latency": {"before": before["latency"], "after": after["latency"]},
        "tasks": details
    }


def markdown(result):
    lines = ["# W8 patch comparison (measured data only)", "",
             "| Metric | Before | After | Change |", "| --- | ---: | ---: | ---: |"]
    for group in ("w7", "taint_provenance"):
        item = result[group]
        lines.append(f"| {group} ASR (n={item['n']}) | {item['before']:.1%} | {item['after']:.1%} | {item['delta']:+.1%} |")
    for group in ("utility", "fpr"):
        item = result[group]
        lines.append(f"| {group} | {item['before']:.1%} | {item['after']:.1%} | {item['after'] - item['before']:+.1%} |")
    lines += ["", "| Task | Before | After | Before tries | After tries |",
              "| --- | --- | --- | ---: | ---: |"]
    for item in result["tasks"]:
        lines.append(f"| {item['task']} | {item['before']} | {item['after']} | {item['tries_before']} | {item['tries_after']} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error("output directory must be empty")
    before = json.loads(args.before.read_text(encoding="utf-8"))
    after = json.loads(args.after.read_text(encoding="utf-8"))
    result = compare(before, after)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (args.output_dir / "comparison.md").write_text(markdown(result), encoding="utf-8")
    print(markdown(result), end="")


if __name__ == "__main__":
    main()
