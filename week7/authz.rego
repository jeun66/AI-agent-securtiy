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
    input.action == "write_file"
}

decision := {"allow": allow, "requires_approval": requires_approval}
