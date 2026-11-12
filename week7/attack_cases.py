"""Scripted local identity, delegation, command, and approval scenarios."""

from dataclasses import dataclass, replace
from time import time

from nacl.signing import SigningKey

from week7.commands import Command, forward_command, sign_command
from week7.credentials import issue_credential
from week7.delegation import CAPABILITY_TYPE, DelegationVerifier, issue_capability
from week7.gateway import Invocation
from week7.identity import generate_identity
from week7.scope import Grant, encode_grants
from week7.signed_tokens import sign_token, verify_token


READ = Grant("read_file", "note.txt")
WRITE = Grant("write_file", "note.txt")
READ_BLOCKED = Grant("read_file", "blocked.txt")
AUDIENCE = "urn:agent-trust:gateway:w7"
ORIGINAL_NOTE = "W7 sandbox note\n"
BLOCKED_NOTE = "W7 policy-protected data\n"
APPROVED_CONTENT = "W7 approved replacement\n"


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    kind: str
    title: str


SCENARIOS = (
    Scenario("impersonation", "attack", "다른 에이전트의 DID 사칭"),
    Scenario("token_forgery", "attack", "위임 토큰 서명 위조"),
    Scenario("scope_expansion", "attack", "정상 키로 서명한 하위 권한 확대"),
    Scenario("expired_capability", "attack", "만료된 위임 토큰 사용"),
    Scenario("revoked_parent", "attack", "회수된 상위 토큰의 하위 위임 사용"),
    Scenario("changed_command", "attack", "중간 에이전트의 최초 명령 변경"),
    Scenario("policy_escape", "attack", "OPA 허용 목록 밖의 로컬 파일 읽기"),
    Scenario("unapproved_write", "attack", "사용자 승인 없이 파일 변경"),
    Scenario("approval_swap", "attack", "승인 후 쓰기 내용 변경"),
    Scenario("approval_replay", "attack", "소모된 승인 토큰 재사용"),
    Scenario("path_traversal", "attack", "공통 경로 검증을 우회하는 상위 경로 읽기"),
    Scenario("normal_read", "normal", "정상 위임 파일 읽기"),
    Scenario("normal_write", "normal", "정상 승인 파일 쓰기"),
    Scenario("opa_unavailable", "fault", "OPA 실행 파일 사용 불가"),
)


@dataclass(frozen=True, slots=True)
class Trial:
    actor: str
    actor_key: SigningKey
    user_key: SigningKey
    verifier: DelegationVerifier
    invocation: Invocation
    review_invocation: Invocation | None = None


def prepare_trial(case: Scenario) -> Trial:
    now = int(time())
    issuer, issuer_key = generate_identity()
    user, user_key = generate_identity()
    middle, middle_key = generate_identity()
    actor, actor_key = generate_identity()
    all_grants = {READ, WRITE, READ_BLOCKED}
    parent_grants = {WRITE} if case.id == "scope_expansion" else all_grants
    child_grants = set() if case.id == "scope_expansion" else all_grants
    credential = issue_credential(issuer_key, user, AUDIENCE, all_grants,
                                  valid_from=now - 120, valid_until=now + 600)
    root = issue_capability(user_key, middle, AUDIENCE, parent_grants, credential=credential,
                            issued_at=now - 60, expires_at=now + 480, remaining_depth=1)
    leaf = issue_capability(middle_key, actor, AUDIENCE, child_grants, credential=credential,
                            issued_at=now - 30, expires_at=now - 1 if case.id == "expired_capability" else now + 360,
                            parent=root)
    verifier = DelegationVerifier(AUDIENCE, trusted_issuers={issuer}, ceiling=all_grants,
                                  user_policies={user: all_grants})
    if case.id == "revoked_parent":
        verifier.revoke(root)
    elif case.id == "scope_expansion":
        _, claims = verify_token(leaf, CAPABILITY_TYPE)
        leaf = sign_token(middle_key, CAPABILITY_TYPE, {**claims, "scope": encode_grants({READ})})
    elif case.id == "token_forgery":
        header, payload, signature = leaf.split(".")
        changed = ("A" if signature[0] != "A" else "B") + signature[1:]
        leaf = f"{header}.{payload}.{changed}"

    def request(command):
        anchor = sign_command(user_key, command)
        first = forward_command(user_key, middle, command, anchor)
        second = forward_command(middle_key, actor, command, first)
        return Invocation(credential, (root, leaf), anchor, (first, second), command)

    if case.id in {"unapproved_write", "approval_swap", "approval_replay", "normal_write"}:
        command = Command(AUDIENCE, "Replace the sandbox note.", WRITE, write_content=APPROVED_CONTENT)
    elif case.id in {"policy_escape", "changed_command"}:
        command = Command(AUDIENCE, "Read the requested sandbox file.", READ_BLOCKED)
    else:
        command = Command(AUDIENCE, "Read the requested sandbox file.", READ)

    invocation = request(command)
    review = invocation if case.id in {"normal_write", "approval_swap", "approval_replay"} else None
    if case.id == "approval_swap":
        invocation = request(replace(command, write_content="W7 unapproved replacement\n"))
    elif case.id == "changed_command":
        changed = replace(command, instruction="Read the file selected by the middle agent.", grant=READ)
        hop = forward_command(middle_key, actor, changed, invocation.hops[0])
        invocation = replace(invocation, received=changed, hops=(invocation.hops[0], hop))
    if case.id == "impersonation":
        _, actor_key = generate_identity()
    return Trial(actor, actor_key, user_key, verifier, invocation, review)
