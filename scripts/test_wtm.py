"""Tests for scripts/wtm.py.

Run with: python3 -m unittest discover -s scripts -p 'test_wtm.py'
"""

import contextlib
import io
import pathlib
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import wtm


def run_git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


class TestRemoveWorktreeKeepDir(unittest.TestCase):
    def test_keep_dir_does_not_call_git_worktree_remove(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            worktree_path = root / "repo_feature"
            worktree_path.mkdir()
            common_dir = root / "repo" / ".git"
            admin_dir = common_dir / "worktrees" / "repo_feature"
            admin_dir.mkdir(parents=True)
            (worktree_path / ".git").write_text(f"gitdir: {admin_dir}\n")
            calls = []

            def fake_run_command(cmd, **kwargs):
                calls.append(cmd)
                if cmd == ["git", "worktree", "list"]:
                    return SimpleNamespace(stdout=f"{worktree_path} abc123 [feature]\n")
                if cmd == [
                    "git",
                    "-C",
                    str(worktree_path),
                    "rev-parse",
                    "--git-common-dir",
                ]:
                    return SimpleNamespace(stdout=f"{common_dir}\n", returncode=0)
                if cmd == [
                    "git",
                    "--git-dir",
                    str(common_dir),
                    "worktree",
                    "prune",
                    "--expire",
                    "now",
                ]:
                    admin_dir.rmdir()
                return SimpleNamespace(stdout="", returncode=0)

            with (
                mock.patch("builtins.input", return_value="yes"),
                mock.patch.object(wtm, "run_command", side_effect=fake_run_command),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(wtm.remove_worktree(str(worktree_path), keep_dir=True))

            self.assertTrue(worktree_path.exists())
            self.assertFalse(
                any(call[:3] == ["git", "worktree", "remove"] for call in calls),
                "keep_dir=True must not invoke destructive git worktree remove",
            )

    def test_preserve_helper_removes_only_git_pointer_and_prunes_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            worktree_path = root / "repo_feature"
            worktree_path.mkdir()
            common_dir = root / "repo" / ".git"
            admin_dir = common_dir / "worktrees" / "repo_feature"
            admin_dir.mkdir(parents=True)
            (worktree_path / ".git").write_text(f"gitdir: {admin_dir}\n")
            untracked_file = worktree_path / "notes.txt"
            untracked_file.write_text("do not delete me\n")
            calls = []

            def fake_run_command(cmd, **kwargs):
                calls.append(cmd)
                if cmd == [
                    "git",
                    "-C",
                    str(worktree_path),
                    "rev-parse",
                    "--git-common-dir",
                ]:
                    return SimpleNamespace(stdout=f"{common_dir}\n", returncode=0)
                if cmd == [
                    "git",
                    "--git-dir",
                    str(common_dir),
                    "worktree",
                    "prune",
                    "--expire",
                    "now",
                ]:
                    admin_dir.rmdir()
                return SimpleNamespace(stdout="", returncode=0)

            with (
                mock.patch.object(wtm, "run_command", side_effect=fake_run_command),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(wtm.unregister_worktree_preserving_dir(worktree_path))

            self.assertFalse((worktree_path / ".git").exists())
            self.assertEqual(untracked_file.read_text(), "do not delete me\n")
            self.assertIn(
                ["git", "--git-dir", str(common_dir), "worktree", "prune", "--expire", "now"],
                calls,
            )

    def test_preserve_helper_restores_git_pointer_when_metadata_remains(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            worktree_path = root / "repo_feature"
            worktree_path.mkdir()
            common_dir = root / "repo" / ".git"
            admin_dir = common_dir / "worktrees" / "repo_feature"
            admin_dir.mkdir(parents=True)
            git_file = worktree_path / ".git"
            git_file_contents = f"gitdir: {admin_dir}\n"
            git_file.write_text(git_file_contents)

            def fake_run_command(cmd, **kwargs):
                if cmd == [
                    "git",
                    "-C",
                    str(worktree_path),
                    "rev-parse",
                    "--git-common-dir",
                ]:
                    return SimpleNamespace(stdout=f"{common_dir}\n", returncode=0)
                return SimpleNamespace(stdout="", returncode=0)

            with (
                mock.patch.object(wtm, "run_command", side_effect=fake_run_command),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertFalse(wtm.unregister_worktree_preserving_dir(worktree_path))

            self.assertEqual(git_file.read_text(), git_file_contents)
            self.assertTrue(admin_dir.exists())

    def test_preserve_helper_dry_run_does_not_remove_git_pointer(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            worktree_path = root / "repo_feature"
            worktree_path.mkdir()
            common_dir = root / "repo" / ".git"
            admin_dir = common_dir / "worktrees" / "repo_feature"
            admin_dir.mkdir(parents=True)
            git_file = worktree_path / ".git"
            git_file.write_text(f"gitdir: {admin_dir}\n")
            calls = []

            def fake_run_command(cmd, **kwargs):
                calls.append(cmd)
                if cmd == [
                    "git",
                    "-C",
                    str(worktree_path),
                    "rev-parse",
                    "--git-common-dir",
                ]:
                    return SimpleNamespace(stdout=f"{common_dir}\n", returncode=0)
                return SimpleNamespace(stdout="", returncode=0)

            with (
                mock.patch.object(wtm, "DRY_RUN", True),
                mock.patch.object(wtm, "run_command", side_effect=fake_run_command),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(wtm.unregister_worktree_preserving_dir(worktree_path))

            self.assertTrue(git_file.exists())
            self.assertNotIn(
                ["git", "--git-dir", str(common_dir), "worktree", "prune", "--expire", "now"],
                calls,
            )

    def test_keep_dir_preserves_modified_and_untracked_files_in_real_repo(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            repo = root / "repo"
            worktree_path = root / "repo_feature"
            repo.mkdir()

            run_git(repo, "init")
            (repo / "tracked.txt").write_text("base\n")
            run_git(repo, "add", "tracked.txt")
            run_git(
                repo,
                "-c",
                "user.name=wtm test",
                "-c",
                "user.email=wtm@example.com",
                "commit",
                "-m",
                "initial",
            )
            run_git(repo, "worktree", "add", "-b", "feature", str(worktree_path))

            (worktree_path / "tracked.txt").write_text("modified\n")
            untracked_file = worktree_path / "untracked.txt"
            untracked_file.write_text("draft\n")

            with (
                contextlib.chdir(repo),
                mock.patch("builtins.input", return_value="yes"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(wtm.remove_worktree(str(worktree_path), keep_dir=True))

            self.assertTrue(worktree_path.exists())
            self.assertEqual((worktree_path / "tracked.txt").read_text(), "modified\n")
            self.assertEqual(untracked_file.read_text(), "draft\n")
            worktree_list = run_git(repo, "worktree", "list", "--porcelain").stdout
            self.assertNotIn(str(worktree_path), worktree_list)

    def test_remove_without_keep_dir_uses_git_remove_and_rmtree_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            worktree_path = pathlib.Path(d) / "repo_feature"
            worktree_path.mkdir()
            calls = []

            def fake_run_command(cmd, **kwargs):
                calls.append(cmd)
                if cmd == ["git", "worktree", "list"]:
                    return SimpleNamespace(stdout=f"{worktree_path} abc123 [feature]\n")
                return SimpleNamespace(stdout="", returncode=0)

            with (
                mock.patch("builtins.input", return_value="yes"),
                mock.patch.object(wtm, "run_command", side_effect=fake_run_command),
                mock.patch.object(wtm.shutil, "rmtree") as rmtree,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(wtm.remove_worktree(str(worktree_path), keep_dir=False))

            self.assertIn(["git", "worktree", "remove", str(worktree_path)], calls)
            rmtree.assert_called_once_with(worktree_path)


if __name__ == "__main__":
    unittest.main()
