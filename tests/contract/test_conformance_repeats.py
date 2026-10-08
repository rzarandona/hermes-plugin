from tools import run_conformance


def test_each_repeat_runs_a_fresh_process_and_retains_its_own_failure(monkeypatch):
    groups = run_conformance.validate(run_conformance.load_cases())[:1]
    calls = []

    class Completed:
        stdout = ""
        stderr = "fixture failure"

        def __init__(self, returncode):
            self.returncode = returncode

    def run(command, **kwargs):
        calls.append(command)
        return Completed(1 if len(calls) == 1 else 0)

    monkeypatch.setattr(run_conformance.subprocess, "run", run)
    result = run_conformance.execute(groups, repeat=2)["results"][0]
    assert len(calls) == 2
    assert [schedule["passed"] for schedule in result["schedule_executions"]] == [False, True]
    assert result["status"] == "failed"


def test_bundle_content_and_digest_normalize_only_text_line_endings(tmp_path):
    from tools.build_release import digest

    text = tmp_path / "document.md"
    text.write_bytes(b"hello\r\nworld\r\n")
    first = digest(text)
    text.write_bytes(b"hello\nworld\n")
    assert digest(text) == first
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n")
    first = digest(binary)
    binary.write_bytes(b"\x89PNG\n")
    assert digest(binary) != first


def test_missing_package_inputs_fail_before_writing_bundle(tmp_path, monkeypatch):
    import pytest

    from tools import build_release

    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    target = tmp_path / "inspection.zip"
    with pytest.raises(FileNotFoundError):
        build_release.write_bundle(target)
    assert not target.exists()


def test_index_build_without_a_wheel_does_not_write_false_release_inventory(tmp_path, monkeypatch):
    import pytest

    from tools import build_release

    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    (tmp_path / "release").mkdir()
    bundle = tmp_path / "dist" / "plugin.zip"
    bundle.parent.mkdir()
    bundle.write_bytes(b"fixture")
    with pytest.raises(FileNotFoundError):
        build_release.write_indexes(bundle)
    assert not (tmp_path / "release" / "package-inventory.json").exists()
