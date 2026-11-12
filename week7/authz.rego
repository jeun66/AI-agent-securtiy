package agent.authz

import rego.v1

default permitted := false

permitted if {
    input.resource == "note.txt"
    input.action in {"read_file", "write_file"}
}

default allow := false

allow if {
    is_string(input.actor)
    input.actor != ""
    input.authenticated == true
    input.delegation_valid == true
    input.command_integrity == true
    permitted
}

default requires_approval := false

requires_approval if {
    allow
    tool_requires_approval
}

default tool_requires_approval := false

tool_requires_approval if {
    permitted
    input.action == "write_file"
}

policy_version := "w7-file-policy-v1"

decision := {
    "allow": allow,
    "requires_approval": requires_approval,
    "policy_version": policy_version,
}

policy_only_decision := {
    "allow": permitted,
    "requires_approval": tool_requires_approval,
    "policy_version": policy_version,
}
