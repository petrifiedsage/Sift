def classify_score(score: int) -> str:
    """
    Convert numeric score into severity level.
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"
    
def compute_score(base_score: int, *, in_config_file: bool = False) -> int:
    """
    Compute final risk score based on context.
    """
    score = base_score

    # Config files are more dangerous
    if in_config_file:
        score += 10

    return min(score, 100)
