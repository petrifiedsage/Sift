def print_report(findings):
    if not findings:
        print("✅ No secrets detected")
        return

    print("\n🚨 Potential secrets detected:\n")
    for f in findings:
        extra = f" | entropy={f['entropy']}" if "entropy" in f else ""
        print(
            f"{f['file']}:{f['line']} | "
            f"{f['classification']:<8} | "
            f"Score: {f['score']} | "
            f"{f['rule_id']}{extra}"
        )


