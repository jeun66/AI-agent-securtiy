package agent.authz_test

import rego.v1
import data.agent.authz.decision
import data.agent.authz.policy_only_decision

valid_input := {
    "actor": "authenticated-lab-agent",
    "authenticated": true,
    "delegation_valid": true,
    "command_integrity": true,
    "action": "read_file",
    "resource": "note.txt",
}

test_verified_read if {
    result := decision with input as valid_input
    result == {"allow": true, "requires_approval": false, "policy_version": "w7-file-policy-v1"}
}

test_verified_write_requires_approval if {
    result := decision with input as object.union(valid_input, {"action": "write_file"})
    result == {"allow": true, "requires_approval": true, "policy_version": "w7-file-policy-v1"}
}

test_each_attestation_is_required[field] if {
    some field in {"actor", "authenticated", "delegation_valid", "command_integrity"}
    missing := object.remove(valid_input, {field})
    result := decision with input as missing
    result == {"allow": false, "requires_approval": false, "policy_version": "w7-file-policy-v1"}
}

test_default_deny_other_resources if {
    result := decision with input as object.union(valid_input, {"resource": "evil.txt"})
    result == {"allow": false, "requires_approval": false, "policy_version": "w7-file-policy-v1"}
}

test_policy_only_requires_approval_without_asserting_identity if {
    result := policy_only_decision with input as {"action": "write_file", "resource": "note.txt"}
    result == {"allow": true, "requires_approval": true, "policy_version": "w7-file-policy-v1"}
}
