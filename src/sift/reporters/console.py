def print_report(findings):
    if not findings:
        print("✅ No secrets detected")
        return

    print("\n🚨 Potential secrets detected:\n")
    for f in findings:
        print(
            f"{f['file']}:{f['line']} | "
            f"{f['classification']} | "
            f"Score: {f['score']}"
        )
