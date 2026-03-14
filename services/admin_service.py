"""
Admin functions for ymmy - cost monitoring, quality control, and processing insights.
"""
from typing import Any, Dict, List
from services.news_service import (
    get_processing_stats,
    get_quality_issues,
    resolve_quality_issue,
    get_processing_log,
)


def get_admin_dashboard() -> Dict[str, Any]:
    """Get comprehensive admin dashboard data."""
    stats = get_processing_stats()
    
    # Get recent quality issues
    recent_issues = get_quality_issues(limit=10, resolved=False)
    
    # Get recent processing activity
    recent_activity = get_processing_log(limit=15)
    
    return {
        "stats": stats,
        "recent_issues": recent_issues,
        "recent_activity": recent_activity,
    }


def get_cost_breakdown() -> Dict[str, Any]:
    """Detailed cost analysis by language and level."""
    stats = get_processing_stats()
    
    # TODO: Add per-language/level breakdown when we have that data
    return {
        "overall": stats,
        "by_language": {},  # Placeholder for future enhancement
        "by_level": {},     # Placeholder for future enhancement
    }


def get_quality_control_summary() -> Dict[str, Any]:
    """Summary of quality control issues."""
    all_issues = get_quality_issues(limit=1000, resolved=False)
    resolved_issues = get_quality_issues(limit=1000, resolved=True)
    
    # Group by issue type
    by_type = {}
    for issue in all_issues:
        issue_type = issue.get("issue_type", "unknown")
        by_type[issue_type] = by_type.get(issue_type, 0) + 1
    
    # Group by language
    by_language = {}
    for issue in all_issues:
        lang = issue.get("target_language", "unknown")
        by_language[lang] = by_language.get(lang, 0) + 1
    
    return {
        "open_issues": len(all_issues),
        "resolved_issues": len(resolved_issues),
        "by_type": by_type,
        "by_language": by_language,
        "recent_issues": all_issues[:20],
    }


def resolve_multiple_issues(issue_ids: List[int]) -> Dict[str, Any]:
    """Resolve multiple quality issues at once."""
    success_count = 0
    for issue_id in issue_ids:
        if resolve_quality_issue(issue_id):
            success_count += 1
    
    return {
        "resolved": success_count,
        "total": len(issue_ids),
    }
