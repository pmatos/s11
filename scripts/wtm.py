#!/usr/bin/env python3
"""
Worktree Management (wtm) - Git worktree creation and removal script.

This script automates the process of managing git worktrees with full environment setup:

CREATE command:
1. Creates a new git worktree from specified branch
2. Sets up a virtual environment (_venv)
3. Installs dependencies using uv sync

REMOVE command:
1. Removes the git worktree registration
2. Optionally removes the directory and all contents

Usage:
    python scripts/wtm.py create <branch-name> [worktree-path]
    python scripts/wtm.py remove <branch-or-path> [--keep-dir]
    python scripts/wtm.py list

Examples:
    python scripts/wtm.py create feature/new-feature
    python scripts/wtm.py create fix/bug-123 ../custom-path
    python scripts/wtm.py remove feature/new-feature
    python scripts/wtm.py remove ../project_feature-new-feature --keep-dir
    python scripts/wtm.py list
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Global flags for verbose and dry run modes
VERBOSE = False
DRY_RUN = False


def validate_branch_name(branch_name):
    """Validate branch name for safety and git compatibility."""
    if not branch_name:
        raise ValueError("Branch name cannot be empty")

    if branch_name.startswith("-"):
        raise ValueError("Branch name cannot start with '-'")

    if ".." in branch_name:
        raise ValueError("Branch name cannot contain '..'")

    if branch_name in ["HEAD", "FETCH_HEAD", "ORIG_HEAD"]:
        raise ValueError(f"Reserved branch name: {branch_name}")

    # Check for dangerous characters beyond filesystem safety
    dangerous_chars = ["$", "`", ";", "|", "&", "(", ")"]
    for char in dangerous_chars:
        if char in branch_name:
            raise ValueError(f"Branch name cannot contain dangerous character: {char}")

    # Check git ref format
    try:
        run_command(
            ["git", "check-ref-format", f"refs/heads/{branch_name}"],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        raise ValueError(f"Invalid branch name format for git: {branch_name}") from None


def validate_custom_path(path):
    """Validate custom path for safety and accessibility."""
    path_obj = Path(path).resolve()

    # Check for path traversal attempts
    if ".." in str(path_obj):
        raise ValueError("Custom path cannot contain '..' (path traversal)")

    # Validate parent directory exists and is writable
    parent = path_obj.parent
    if not parent.exists():
        raise ValueError(f"Parent directory does not exist: {parent}")

    if not os.access(parent, os.W_OK):
        raise ValueError(f"No write permission for parent directory: {parent}")

    return path_obj


def run_command(cmd, cwd=None, check=True, capture_output=False, env=None):
    """Run a command and handle errors appropriately."""
    if isinstance(cmd, str):
        raise ValueError("Commands must be provided as lists for security reasons")

    if VERBOSE or not capture_output:
        print(f"🔧 Running: {' '.join(cmd)}")
        if cwd:
            print(f"   Working directory: {cwd}")

    if DRY_RUN:
        print("   [DRY RUN] Command would be executed here")

        # Return a mock result for dry run
        class MockResult:
            def __init__(self):
                self.returncode = 0
                self.stdout = ""
                self.stderr = ""

        return MockResult()

    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=check,
            shell=False,
            capture_output=capture_output,
            text=True,
            env=env,
        )

        if VERBOSE and capture_output:
            if result.stdout:
                print(f"   stdout: {result.stdout.strip()}")
            if result.stderr:
                print(f"   stderr: {result.stderr.strip()}")

        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed with exit code {e.returncode}")
        if e.stdout:
            print(f"stdout: {e.stdout}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        raise


def canonicalize_branch_name(branch_name):
    """Convert branch name to filesystem-safe name."""
    return re.sub(r'[/\\:*?"<>|]', "-", branch_name)


def check_branch_exists(branch_name):
    """Check if the specified branch exists locally or remotely."""
    print(f"🔍 Checking if branch '{branch_name}' exists...")

    try:
        # Check both local and remote refs in a single command
        result = run_command(
            ["git", "show-ref", f"refs/heads/{branch_name}", f"refs/remotes/origin/{branch_name}"],
            capture_output=True,
            check=False,
        )

        if result.returncode == 0:
            refs = result.stdout.strip()
            if f"refs/heads/{branch_name}" in refs:
                print(f"✅ Found local branch: {branch_name}")
                return True
            elif f"refs/remotes/origin/{branch_name}" in refs:
                print(f"✅ Found remote branch: origin/{branch_name}")
                return True
    except subprocess.CalledProcessError:
        pass

    print(f"⚠️  Branch '{branch_name}' not found locally or remotely")
    return False


def create_branch_if_needed(branch_name):
    """Create a new branch if it doesn't exist."""
    print(f"🌱 Creating new branch: {branch_name}")

    try:
        run_command(["git", "branch", branch_name])
        print(f"✅ Created new branch: {branch_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create branch: {e}")
        return False


def show_available_branches():
    """Show available branches without pagination."""
    print("\n💡 Available branches:")
    try:
        result = run_command(
            ["git", "--no-pager", "branch", "-a"], capture_output=True, check=False
        )
        if result.returncode == 0:
            branches = result.stdout.strip().split("\n")
            # Show only first 20 branches to avoid overwhelming output
            for branch in branches[:20]:
                print(f"   {branch.strip()}")
            if len(branches) > 20:
                print(f"   ... and {len(branches) - 20} more branches")
        else:
            print("   Could not retrieve branch list")
    except subprocess.CalledProcessError:
        print("   Could not retrieve branch list")


def get_worktree_path(branch_name, custom_path=None):
    """Determine the worktree path."""
    if custom_path:
        return validate_custom_path(custom_path)

    # Default: sibling directory with canonicalized branch name
    current_dir = Path.cwd()
    project_name = current_dir.name
    safe_branch_name = canonicalize_branch_name(branch_name)
    worktree_name = f"{project_name}_{safe_branch_name}"
    return current_dir.parent / worktree_name


def check_worktree_exists(worktree_path):
    """Check if worktree already exists."""
    if worktree_path.exists():
        print(f"❌ Worktree path already exists: {worktree_path}")
        return True

    # Check if it's already registered as a worktree
    try:
        result = run_command(["git", "worktree", "list"], capture_output=True)
        for line in result.stdout.splitlines():
            if str(worktree_path) in line:
                print(f"❌ Worktree already registered: {worktree_path}")
                return True
    except subprocess.CalledProcessError:
        pass

    return False


def create_worktree(branch_name, worktree_path):
    """Create a new git worktree."""
    print(f"📁 Creating worktree at: {worktree_path}")
    run_command(["git", "worktree", "add", str(worktree_path), branch_name])
    print("✅ Worktree created successfully")


def setup_uv_environment(worktree_path):
    """Set up uv environment and install dependencies."""
    print("📦 Setting up uv environment...")

    # Check if uv is available
    try:
        run_command(["uv", "--version"], capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ uv is not installed or not in PATH")
        print("   Please install uv: curl -LsSf https://astral.sh/uv/install.sh | sh")
        return False

    # Install dependencies using uv sync
    try:
        run_command(["uv", "sync", "--dev"], cwd=worktree_path)
        print("✅ Dependencies installed with uv")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies with uv: {e}")
        return False


def find_worktree_by_branch(branch_name):
    """Find existing worktree by branch name."""
    try:
        result = run_command(["git", "worktree", "list", "--porcelain"], capture_output=True)
        worktrees = {}
        current_path = None

        for line in result.stdout.splitlines():
            if line.startswith("worktree "):
                current_path = line[9:]  # Remove "worktree " prefix
            elif line.startswith("branch ") and current_path:
                branch = line[7:]  # Remove "branch " prefix
                if branch.startswith("refs/heads/"):
                    branch = branch[11:]  # Remove "refs/heads/" prefix
                worktrees[branch] = current_path
                current_path = None

        return worktrees.get(branch_name)
    except subprocess.CalledProcessError:
        return None


def resolve_gitfile_path(path_text, worktree_path):
    """Resolve a path from a linked-worktree .git file."""
    path = Path(path_text)
    if not path.is_absolute():
        path = worktree_path / path
    return path.resolve()


def unregister_worktree_preserving_dir(worktree_path):
    """Unregister a linked worktree without deleting its directory contents."""
    git_file = worktree_path / ".git"
    if not git_file.exists():
        print(f"❌ Cannot preserve '{worktree_path}': missing .git pointer")
        return False
    if git_file.is_dir():
        print(
            f"❌ Cannot preserve '{worktree_path}': "
            ".git is a directory, not a worktree pointer"
        )
        return False

    try:
        common_dir_result = run_command(
            ["git", "-C", str(worktree_path), "rev-parse", "--git-common-dir"],
            capture_output=True,
        )
        common_dir_text = common_dir_result.stdout.strip()
        if not common_dir_text:
            print(f"❌ Cannot preserve '{worktree_path}': git common dir is empty")
            return False
        common_dir = resolve_gitfile_path(common_dir_text, worktree_path)

        git_file_contents = git_file.read_text()
        git_file_lines = git_file_contents.splitlines()
        first_line = git_file_lines[0] if git_file_lines else ""
        if not first_line.startswith("gitdir:"):
            print(f"❌ Cannot preserve '{worktree_path}': malformed .git pointer")
            return False

        admin_gitdir = resolve_gitfile_path(first_line[len("gitdir:") :].strip(), worktree_path)
        worktrees_dir = (common_dir / "worktrees").resolve()
        if not admin_gitdir.is_relative_to(worktrees_dir):
            print(
                f"❌ Cannot preserve '{worktree_path}': worktree metadata is outside {worktrees_dir}"
            )
            return False
        if not admin_gitdir.exists():
            print(f"❌ Cannot preserve '{worktree_path}': worktree metadata is missing")
            return False

        if DRY_RUN:
            print("   [DRY RUN] Would remove .git pointer and prune worktree metadata")
            return True

        git_file.unlink()
        try:
            run_command(
                ["git", "--git-dir", str(common_dir), "worktree", "prune", "--expire", "now"]
            )
            if admin_gitdir.exists():
                raise RuntimeError(f"worktree metadata still exists: {admin_gitdir}")
            if not worktree_path.exists():
                raise RuntimeError(f"preserved directory disappeared: {worktree_path}")
        except Exception as e:
            if not git_file.exists():
                git_file.write_text(git_file_contents)
            print(f"❌ Failed to unregister worktree while preserving directory: {e}")
            return False

        return True
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"❌ Failed to unregister worktree while preserving directory: {e}")
        return False


def remove_worktree(branch_or_path, keep_dir=False):
    """Remove a worktree and optionally its directory."""
    worktree_path = None

    # Check if argument is a path or branch name
    potential_path = Path(branch_or_path)
    if potential_path.exists():
        worktree_path = potential_path.resolve()
        print(f"🔍 Using provided path: {worktree_path}")
    else:
        # Try to find worktree by branch name
        found_path = find_worktree_by_branch(branch_or_path)
        if found_path:
            worktree_path = Path(found_path)
            print(f"🔍 Found worktree for branch '{branch_or_path}': {worktree_path}")
        else:
            # Try default path pattern
            worktree_path = get_worktree_path(branch_or_path)
            if not worktree_path.exists():
                print(f"❌ Could not find worktree for '{branch_or_path}'")
                print(f"   Tried: {worktree_path}")
                return False
            print(f"🔍 Using default path pattern: {worktree_path}")

    # Verify it's actually a worktree
    try:
        result = run_command(["git", "worktree", "list"], capture_output=True)
        is_worktree = False
        for line in result.stdout.splitlines():
            if str(worktree_path) in line:
                is_worktree = True
                break

        if not is_worktree:
            print(f"❌ '{worktree_path}' is not a registered git worktree")
            return False
    except subprocess.CalledProcessError:
        print("❌ Could not verify worktree status")
        return False

    # Safety confirmation
    print(f"⚠️  About to remove worktree: {worktree_path}")
    if not keep_dir:
        print("⚠️  This will also DELETE the entire directory and all its contents!")

    try:
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        if confirm not in ["yes", "y"]:
            print("❌ Operation cancelled")
            return False
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled")
        return False

    # Remove the worktree
    try:
        print("🗑️  Removing worktree registration...")
        if keep_dir:
            if not unregister_worktree_preserving_dir(worktree_path):
                return False
        else:
            # Remove worktree and let git handle directory removal
            run_command(["git", "worktree", "remove", str(worktree_path)])

            # If directory still exists, remove it manually
            if worktree_path.exists():
                print("🗑️  Removing directory...")
                shutil.rmtree(worktree_path)

        print("✅ Worktree removed successfully")
        if keep_dir:
            print(f"📂 Directory preserved: {worktree_path}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to remove worktree: {e}")
        return False
    except Exception as e:
        print(f"❌ Error during removal: {e}")
        return False


def cmd_create(args):
    """Handle the create subcommand."""
    branch_name = args.branch

    print(f"🚀 Creating worktree for branch: {branch_name}")
    print(f"📂 Current directory: {Path.cwd()}")

    # Validate branch name first
    try:
        validate_branch_name(branch_name)
    except ValueError as e:
        print(f"❌ Invalid branch name: {e}")
        sys.exit(1)

    # Check if branch exists, create if needed
    if not check_branch_exists(branch_name):
        print(f"🌱 Branch '{branch_name}' doesn't exist. Creating it...")
        if not create_branch_if_needed(branch_name):
            show_available_branches()
            sys.exit(1)

    # Determine worktree path
    try:
        worktree_path = get_worktree_path(branch_name, args.path)
        print(f"📍 Worktree path: {worktree_path}")
    except ValueError as e:
        print(f"❌ Invalid path: {e}")
        sys.exit(1)

    # Check if worktree already exists
    if check_worktree_exists(worktree_path):
        sys.exit(1)

    try:
        # Create worktree
        create_worktree(branch_name, worktree_path)

        # Set up uv environment and install dependencies
        if not setup_uv_environment(worktree_path):
            print("⚠️  Failed to set up uv environment, but worktree is created")

        print("\n🎉 Worktree setup complete!")
        print(f"📂 Worktree location: {worktree_path}")
        print("📦 Dependencies managed by uv")
        print("\n💡 To start working:")
        print(f"   cd {worktree_path}")
        print("   # Start developing!")

    except subprocess.CalledProcessError as e:
        print(f"\n❌ Setup failed: {e}")
        # Try to clean up worktree if it was created
        print("🧹 Attempting cleanup of worktree...")
        try:
            # Check if worktree is registered first
            result = run_command(["git", "worktree", "list"], capture_output=True, check=False)
            if result.returncode == 0 and str(worktree_path) in result.stdout:
                run_command(["git", "worktree", "remove", "--force", str(worktree_path)])
                print("✅ Worktree cleanup completed")
            elif worktree_path.exists():
                print(f"⚠️  Manual cleanup may be needed: {worktree_path}")
        except subprocess.CalledProcessError:
            if worktree_path.exists():
                print(f"⚠️  Manual cleanup may be needed: {worktree_path}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


def cmd_remove(args):
    """Handle the remove subcommand."""
    branch_or_path = args.branch_or_path
    keep_dir = args.keep_dir

    print(f"🗑️  Removing worktree: {branch_or_path}")

    if remove_worktree(branch_or_path, keep_dir):
        print("✅ Worktree removal completed")
    else:
        sys.exit(1)


def cmd_list(args):
    """Handle the list subcommand."""
    print("📋 Existing worktrees:")

    try:
        result = run_command(["git", "worktree", "list"], capture_output=True)

        if result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0]
                    branch_info = " ".join(parts[1:])

                    # Check if it's the main worktree
                    if path == str(Path.cwd()):
                        print(f"   📂 {path} ({branch_info}) [MAIN]")
                    else:
                        # Extract branch name if available
                        if "[" in branch_info and "]" in branch_info:
                            branch = branch_info[branch_info.find("[") + 1 : branch_info.find("]")]
                            print(f"   📁 {path} → {branch}")
                        else:
                            print(f"   📁 {path} ({branch_info})")
                else:
                    print(f"   📁 {line}")
        else:
            print("   No worktrees found")

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to list worktrees: {e}")
        sys.exit(1)


def main():
    global VERBOSE, DRY_RUN

    parser = argparse.ArgumentParser(
        description=(
            "Worktree Management - Create and remove git worktrees with uv environment setup"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Global flags
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be done without executing"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True

    # Create subcommand
    create_parser = subparsers.add_parser("create", help="Create a new worktree")
    create_parser.add_argument("branch", help="Branch name to create worktree from")
    create_parser.add_argument("path", nargs="?", help="Custom path for worktree (optional)")
    create_parser.set_defaults(func=cmd_create)

    # Remove subcommand
    remove_parser = subparsers.add_parser("remove", help="Remove a worktree")
    remove_parser.add_argument("branch_or_path", help="Branch name or worktree path to remove")
    remove_parser.add_argument(
        "--keep-dir", action="store_true", help="Keep directory, only remove worktree registration"
    )
    remove_parser.set_defaults(func=cmd_remove)

    # List subcommand
    list_parser = subparsers.add_parser("list", help="List existing worktrees")
    list_parser.set_defaults(func=cmd_list)

    args = parser.parse_args()

    # Set global flags
    VERBOSE = args.verbose
    DRY_RUN = args.dry_run

    if DRY_RUN:
        print("🔍 DRY RUN MODE: No changes will be made")
        print()

    args.func(args)


if __name__ == "__main__":
    main()
