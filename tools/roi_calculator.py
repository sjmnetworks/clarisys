#!/usr/bin/env python3
"""
ROI Calculator for OPA Firewall Policy Automation
Calculates HIPS reduction, time savings, and cost benefits.
"""
import json
from datetime import datetime

def calculate_roi_metrics(
    hips_current=24,
    hips_new=3,
    annual_salary=50000,
    hours_per_rule=2,
    rules_processed=1,
    bulk_size=10
):
    """
    Calculate ROI metrics for policy automation.
    
    Args:
        hips_current: Current humans in process (baseline)
        hips_new: Humans needed in new process
        annual_salary: Average salary per HIP in GBP
        hours_per_rule: Time saved per rule per HIP (in hours)
        rules_processed: Number of rules being processed
        bulk_size: Number of rules in a typical bulk operation
    
    Returns:
        dict: Comprehensive ROI metrics
    """
    # Basic calculations
    working_hours_per_year = 2080
    hourly_rate = annual_salary / working_hours_per_year
    
    hips_saved_per_rule = hips_current - hips_new
    hours_saved_per_rule = hips_saved_per_rule * hours_per_rule
    cost_saved_per_rule = hours_saved_per_rule * hourly_rate
    
    # For actual rules processed
    total_hips_freed = hips_saved_per_rule * rules_processed
    total_hours_saved = hours_saved_per_rule * rules_processed
    total_cost_saved = cost_saved_per_rule * rules_processed
    
    # Bulk operation (e.g., 10 rules at once)
    bulk_hips_freed = hips_saved_per_rule * bulk_size
    bulk_hours_saved = hours_saved_per_rule * bulk_size
    bulk_cost_saved = cost_saved_per_rule * bulk_size
    
    # Annual extrapolation (assuming 100 rules per year)
    rules_per_year = 100
    annual_hips_freed = hips_saved_per_rule * rules_per_year
    annual_hours_saved = hours_saved_per_rule * rules_per_year
    annual_cost_saved = cost_saved_per_rule * rules_per_year
    
    return {
        "metadata": {
            "calculated_at": datetime.utcnow().isoformat() + "Z",
            "baseline": {
                "hips_current": hips_current,
                "hips_new": hips_new,
                "hips_saved_per_rule": hips_saved_per_rule,
                "annual_salary_per_hip": f"£{annual_salary:,.2f}",
                "hourly_rate": f"£{hourly_rate:.2f}",
                "hours_per_rule_per_hip": hours_per_rule
            }
        },
        "per_rule": {
            "hips_freed": hips_saved_per_rule,
            "hours_saved": hours_saved_per_rule,
            "cost_saved_gbp": round(cost_saved_per_rule, 2)
        },
        "bulk_operation": {
            "rules": bulk_size,
            "total_hips_freed": bulk_hips_freed,
            "total_hours_saved": bulk_hours_saved,
            "total_cost_saved_gbp": round(bulk_cost_saved, 2),
            "cost_per_rule_gbp": round(bulk_cost_saved / bulk_size, 2)
        },
        "annual_projection": {
            "rules_per_year": rules_per_year,
            "total_hips_freed": annual_hips_freed,
            "total_hours_saved": annual_hours_saved,
            "total_cost_saved_gbp": round(annual_cost_saved, 2),
            "ftes_freed": round(annual_hips_freed / 1, 1),  # Assuming 1 rule per FTE per year metric
            "cost_per_rule_gbp": round(annual_cost_saved / rules_per_year, 2)
        }
    }

if __name__ == "__main__":
    metrics = calculate_roi_metrics()
    print(json.dumps(metrics, indent=2))
