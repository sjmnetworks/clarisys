# Batch wrapper for the standards-only decision rule.
# Lets callers submit {"requests": [...]} in one OPA evaluation, avoiding
# N HTTP round-trips for bulk endpoints.
package policy.request_standards_batch

import data.policy.request_standards

decisions := [d |
    some i
    req := input.requests[i]
    d := request_standards.decision with input as req
]
