import os

from flask import Flask, jsonify, request

app = Flask(__name__)


EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def check_release_gate(data):
    violations = []

    workflow = data["workflow"]
    image = data["image"]

    # Permissions must be exactly the required least-privilege set.
    if workflow["permissions"] != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # Pull requests must use the pull_request trigger.
    if data["event"] == "pull_request":
        if workflow["trigger"] != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # All tests must pass, the complete matrix must finish,
    # and fail-fast must be disabled.
    if (
        workflow["testsPassed"] is not True
        or workflow["matrixComplete"] is not True
        or workflow["failFast"] is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # Official actions owned by "actions" may use version tags.
    # Every other action must use a full 40-character lowercase SHA.
    for action in workflow["actions"]:
        if action["owner"] == "actions":
            continue

        ref = action["ref"]

        if (
            len(ref) != 40
            or any(character not in "0123456789abcdef" for character in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # Container image security checks.
    if image["multiStage"] is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image["runsAsRoot"] is not False:
        violations.append("ROOT_RUNTIME")

    if image["secretMode"] not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image["criticalVulnerabilities"] != 0:
        violations.append("CRITICAL_CVE")

    if image["digestPinned"] is not True:
        violations.append("UNPINNED_IMAGE")

    # Production has additional deployment requirements.
    if data["target"] == "production":
        if (
            data["event"] != "push"
            or data["ref"] != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


@app.post("/release-gate")
def release_gate():
    data = request.get_json()

    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "violations": ["TESTS_INCOMPLETE"]
        }), 400

    return jsonify(check_release_gate(data))


@app.get("/")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000))
    )
