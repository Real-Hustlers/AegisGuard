"""Dashboard-ready benchmark data builder."""

from __future__ import annotations


def build_dashboard_payload(
    aggregated: dict,
) -> dict:
    """
    Convert benchmark aggregation
    into dashboard-friendly metrics.
    """

    components = aggregated.get(
        "components",
        {},
    )

    return {
        "title":
            "AegisGuard Scalability Dashboard",

        "summary": {
            "components_tested":
                len(components),

            "total_events_processed":
                sum(
                    item.get("events", 0)
                    for item in components.values()
                ),
        },

        "performance": components,
    }