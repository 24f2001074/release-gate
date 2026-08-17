from copy import deepcopy

from app import app


SAFE_PREVIEW = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature/test",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {
                "owner": "actions",
                "name": "checkout",
                "ref": "v4"
            },
            {
                "owner": "example-org",
                "name": "example-action",
                "ref": "0123456789abcdef0123456789abcdef01234567"
            }
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}


def post(data):
    return app.test_client().post(
        "/release-gate",
        json=data
    )


def test_safe_preview():
    response = post(SAFE_PREVIEW)

    assert response.status_code == 200

    result = response.get_json()

    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_excess_permission():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["permissions"]["issues"] = "write"

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "EXCESS_PERMISSION" in result["violations"]


def test_unsafe_pr_trigger():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["trigger"] = "pull_request_target"

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in result["violations"]


def test_tests_incomplete():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["testsPassed"] = False

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_fail_fast_must_be_false():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["failFast"] = True

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "TESTS_INCOMPLETE" in result["violations"]


def test_mutable_third_party_action():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["actions"][1]["ref"] = "v1"

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "MUTABLE_ACTION" in result["violations"]


def test_official_action_tag_is_allowed():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["actions"] = [
        {
            "owner": "actions",
            "name": "checkout",
            "ref": "v4"
        }
    ]

    result = post(data).get_json()

    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_single_stage_image():
    data = deepcopy(SAFE_PREVIEW)

    data["image"]["multiStage"] = False

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "SINGLE_STAGE_IMAGE" in result["violations"]


def test_root_runtime():
    data = deepcopy(SAFE_PREVIEW)

    data["image"]["runsAsRoot"] = True

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "ROOT_RUNTIME" in result["violations"]


def test_secret_in_layer():
    data = deepcopy(SAFE_PREVIEW)

    data["image"]["secretMode"] = "copy"

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "SECRET_IN_LAYER" in result["violations"]


def test_critical_cve():
    data = deepcopy(SAFE_PREVIEW)

    data["image"]["criticalVulnerabilities"] = 1

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "CRITICAL_CVE" in result["violations"]


def test_unpinned_image():
    data = deepcopy(SAFE_PREVIEW)

    data["image"]["digestPinned"] = False

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "UNPINNED_IMAGE" in result["violations"]


def test_production_requires_push_main():
    data = deepcopy(SAFE_PREVIEW)

    data["target"] = "production"

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in result["violations"]
    assert "APPROVAL_REQUIRED" in result["violations"]


def test_production_requires_approval():
    data = deepcopy(SAFE_PREVIEW)

    data["target"] = "production"
    data["event"] = "push"
    data["ref"] = "refs/heads/main"

    result = post(data).get_json()

    assert result["decision"] == "block"
    assert "APPROVAL_REQUIRED" in result["violations"]
    assert "INVALID_PRODUCTION_REF" not in result["violations"]


def test_safe_production():
    data = deepcopy(SAFE_PREVIEW)

    data["target"] = "production"
    data["event"] = "push"
    data["ref"] = "refs/heads/main"
    data["workflow"]["environmentApproval"] = True

    result = post(data).get_json()

    assert result["decision"] == "promote"
    assert result["violations"] == []


def test_multiple_failures():
    data = deepcopy(SAFE_PREVIEW)

    data["workflow"]["permissions"] = {
        "contents": "write"
    }

    data["workflow"]["trigger"] = "pull_request_target"
    data["workflow"]["testsPassed"] = False
    data["workflow"]["matrixComplete"] = False
    data["workflow"]["failFast"] = True

    data["workflow"]["actions"] = [
        {
            "owner": "thirdparty",
            "name": "bad-action",
            "ref": "v1"
        }
    ]

    data["image"] = {
        "multiStage": False,
        "runsAsRoot": True,
        "secretMode": "copy",
        "criticalVulnerabilities": 2,
        "digestPinned": False
    }

    result = post(data).get_json()

    expected = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE"
    }

    assert result["decision"] == "block"
    assert set(result["violations"]) == expected
