def print_report(findings):
    if not findings:
        print("[OK] No secrets detected")
        return

    print("\n[INFO] Potential secrets detected:\n")

    for f in findings:
        detectors = []

        for d in sorted(f.get("detectors", [])):
            if d == "high-entropy-string":
                detectors.append("entropy")
            else:
                detectors.append(d)

        detector_str = " | ".join(detectors)

        print(
            f"{f['file']}:{f['line']} | "
            f"{f['classification']:<8} | "
            f"Score: {f['score']} | "
            f"{detector_str}"
        )
