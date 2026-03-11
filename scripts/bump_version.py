#!/usr/bin/env python3
"""
Version Bump Script for DockGuard.

This script automates the process of bumping the version number across the
repository, including:
1. Updating the `VERSION` file.
2. Updating `pyproject.toml`.
3. Updating `frontend/package.json` and `frontend/package-lock.json` via npm.
4. Committing the changes.
5. Creating a git tag for the new version.
6. Pushing the release branch (but NOT the tag — see --push-tag).

Release workflow (master is a protected branch):
  Step 1:  ./scripts/release.sh --minor   # (or --major / --patch)
           Creates the version bump commit + tag locally, then pushes the
           branch so you can open a pull request.
  Step 2:  Merge the pull request on GitHub.
  Step 3:  ./scripts/release.sh --push-tag
           Verifies the tag has been merged to master, then pushes it.
           This triggers the CI Docker build / release pipeline.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd, cwd=None, check=True):
    """Run a shell command and return its stdout."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=check,
            text=True,
            capture_output=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(cmd)}")
        print(e.stderr)
        if check:
            sys.exit(1)
        return ""


def run_cmd_rc(cmd, cwd=None):
    """Run a shell command and return its exit code (no exception on failure)."""
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    return result.returncode


def get_current_version(repo_root):
    """Read the current version from the VERSION file."""
    version_file = repo_root / "VERSION"
    if not version_file.exists():
        print(f"Error: {version_file} not found.")
        sys.exit(1)

    with open(version_file) as f:
        version_str = f.read().strip()

    return version_str


def parse_version(version_str):
    """Parse a version string into a tuple of ints."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version_str)
    if not match:
        print(f"Error: Invalid version format in VERSION file: '{version_str}'. Expected X.Y.Z.")
        sys.exit(1)
    return tuple(map(int, match.groups()))


def calculate_new_version(current_version, bump_type):
    """Calculate the new version based on the bump type."""
    major, minor, patch = current_version

    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Unknown bump type: {bump_type}")


def update_version_file(repo_root, new_version):
    """Update the VERSION file with the new version."""
    version_file = repo_root / "VERSION"
    print(f"Updating {version_file.relative_to(repo_root)}...")
    with open(version_file, "w") as f:
        f.write(f"{new_version}\n")
    return version_file


def update_pyproject_toml(repo_root, new_version):
    """Update the version in pyproject.toml."""
    pyproject_file = repo_root / "pyproject.toml"
    print(f"Updating {pyproject_file.relative_to(repo_root)}...")

    with open(pyproject_file) as f:
        content = f.read()

    # Replace version = "X.Y.Z" with version = "new_version"
    new_content, count = re.subn(
        r'^(version\s*=\s*")[^"]+(")', f"\\g<1>{new_version}\\g<2>", content, flags=re.MULTILINE
    )

    if count == 0:
        print(f"Warning: Could not find version string in {pyproject_file}")
        return None

    with open(pyproject_file, "w") as f:
        f.write(new_content)

    return pyproject_file


def update_frontend_package(repo_root, new_version):
    """Update the frontend version using npm."""
    frontend_dir = repo_root / "frontend"
    print("Updating frontend package versions via npm...")

    # Use npm version to update package.json and package-lock.json without committing
    run_cmd(["npm", "version", str(new_version), "--no-git-tag-version"], cwd=frontend_dir)

    return [frontend_dir / "package.json", frontend_dir / "package-lock.json"]


def update_uv_lock(repo_root):
    """Regenerate uv.lock so it reflects the new project version."""
    lock_file = repo_root / "uv.lock"
    print("Regenerating uv.lock...")
    run_cmd(["uv", "lock"], cwd=repo_root)
    return lock_file


def get_bump_type_interactive():
    """Prompt the user for the bump type."""
    print("\nSelect version bump type:")
    print("1) major - incompatible API changes")
    print("2) minor - add functionality in a backwards compatible manner")
    print("3) patch - backwards compatible bug fixes")
    print("4) custom - enter exact version manually")

    while True:
        choice = input("Enter choice (1-4): ").strip()
        if choice in ("1", "major"):
            return "major"
        elif choice in ("2", "minor"):
            return "minor"
        elif choice in ("3", "patch"):
            return "patch"
        elif choice in ("4", "custom"):
            return "custom"
        print("Invalid choice. Please select 1, 2, 3, or 4.")


def get_current_branch(repo_root):
    """Return the current branch name, or exit if in detached HEAD state."""
    branch = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root)
    if branch == "HEAD":
        print("Error: You are in a detached HEAD state. Please checkout a branch first.")
        sys.exit(1)
    return branch


def cmd_push_tag(repo_root):
    """Push the release tag after verifying it has been merged to master."""
    current_version = get_current_version(repo_root)
    tag = f"v{current_version}"

    # Ensure the tag exists locally
    existing = run_cmd(["git", "tag", "-l", tag], cwd=repo_root)
    if not existing:
        print(f"Error: Local tag '{tag}' not found.")
        print("Run the bump script first (e.g. ./scripts/release.sh --minor).")
        sys.exit(1)

    # Fetch latest origin/master before any checks
    print("Fetching latest origin/master...")
    run_cmd(["git", "fetch", "origin", "master"], cwd=repo_root)

    # Guard: detect stale local checkout — local VERSION differs from origin/master
    remote_version = run_cmd(["git", "show", "origin/master:VERSION"], cwd=repo_root)
    if current_version != remote_version:
        print()
        print("=" * 68)
        print("  !! STOP: YOUR LOCAL CHECKOUT IS OUT OF DATE !!")
        print()
        print(f"  Local VERSION  : {current_version}")
        print(f"  Remote VERSION : {remote_version}")
        print()
        print("  You must pull the latest master before pushing the tag.")
        print("  Run:")
        print()
        print("    git checkout master && git pull origin master")
        print()
        print("  Then re-run:  ./scripts/release.sh --push-tag")
        print("=" * 68)
        print()
        sys.exit(1)

    # Guard: refuse to push the tag until the PR has been merged
    rc = run_cmd_rc(
        ["git", "merge-base", "--is-ancestor", tag, "origin/master"],
        cwd=repo_root,
    )
    if rc != 0:
        print(f"\nError: Tag '{tag}' has not been merged to master yet.")
        print("Merge the pull request first, then re-run:")
        print("  ./scripts/release.sh --push-tag")
        sys.exit(1)

    print(f"\nTag '{tag}' is merged to master. Pushing tag...")
    run_cmd(["git", "push", "origin", tag], cwd=repo_root)
    print(f"\nSuccess! Tag '{tag}' pushed.")
    print("CI will now build and publish the release Docker image.")


def main():
    parser = argparse.ArgumentParser(
        description="Bump DockGuard version.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Release workflow (protected master branch):
  Step 1:  ./scripts/release.sh --minor      # bump, commit, tag, push branch
  Step 2:  Open a pull request and merge it.
  Step 3:  ./scripts/release.sh --push-tag   # verify merged, then push tag → triggers CI
""",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--major", action="store_true", help="Bump major version (X.y.z -> X+1.0.0)")
    group.add_argument("--minor", action="store_true", help="Bump minor version (x.Y.z -> x.Y+1.0)")
    group.add_argument("--patch", action="store_true", help="Bump patch version (x.y.Z -> x.y.Z+1)")
    group.add_argument("--version", type=str, help="Set exact version (e.g., 1.2.3)")
    group.add_argument("--no-commit", action="store_true", help="Update files only; skip git commit, tag, and push")
    group.add_argument(
        "--push-tag",
        action="store_true",
        help="Push the existing local release tag (after PR is merged to master)",
    )

    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

    # ── --push-tag mode ───────────────────────────────────────────────────────
    if args.push_tag:
        cmd_push_tag(repo_root)
        return

    # ── Version bump mode ─────────────────────────────────────────────────────
    current_version_str = get_current_version(repo_root)
    print(f"Current version: {current_version_str}")

    new_version_str = None

    if args.version:
        new_version_str = args.version
        print(f"Setting explicit version: {new_version_str}")
        # Strip 'v' if provided
        if new_version_str.startswith("v"):
            new_version_str = new_version_str[1:]
    else:
        # Determine bump type
        bump_type = None
        if args.major:
            bump_type = "major"
        elif args.minor:
            bump_type = "minor"
        elif args.patch:
            bump_type = "patch"
        else:
            bump_type = get_bump_type_interactive()

        if bump_type == "custom":
            while True:
                custom_ver = input("Enter new version (e.g. 1.0.0): ").strip()
                if custom_ver.startswith("v"):
                    custom_ver = custom_ver[1:]
                if re.match(r"^\d+\.\d+\.\d+$", custom_ver):
                    new_version_str = custom_ver
                    break
                print("Invalid version format. Expected X.Y.Z.")
        else:
            current_version = parse_version(current_version_str)
            new_version_str = calculate_new_version(current_version, bump_type)
            print(f"Calculated new version: {new_version_str}")

            # Require confirmation for interactive mode
            if not any([args.major, args.minor, args.patch]):
                confirm = input(f"Proceed with bump to {new_version_str}? [Y/n] ").strip().lower()
                if confirm not in ("", "y", "yes"):
                    print("Aborting.")
                    sys.exit(0)

    if current_version_str == new_version_str:
        print("Version is unchanged. Exiting.")
        sys.exit(0)

    print("\n--- Making changes ---")
    modified_files = []

    # 1. Update VERSION file
    modified_files.append(update_version_file(repo_root, new_version_str))

    # 2. Update pyproject.toml
    pyproject_file = update_pyproject_toml(repo_root, new_version_str)
    if pyproject_file:
        modified_files.append(pyproject_file)

    # 3. Update frontend
    frontend_files = update_frontend_package(repo_root, new_version_str)
    modified_files.extend(frontend_files)

    # 4. Regenerate uv.lock (it tracks the project's own version)
    modified_files.append(update_uv_lock(repo_root))

    if args.no_commit:
        print("\nSkipping git commit as requested.")
        print("Modified files:")
        for f in modified_files:
            print(f"  - {f.relative_to(repo_root)}")
        return

    print("\n--- Committing changes ---")
    for file_path in modified_files:
        run_cmd(["git", "add", str(file_path)], cwd=repo_root)

    commit_msg = f"Bump version to v{new_version_str}"
    print(f"Creating commit: '{commit_msg}'")
    run_cmd(["git", "commit", "-m", commit_msg], cwd=repo_root)

    print(f"Creating tag: v{new_version_str}")
    run_cmd(["git", "tag", f"v{new_version_str}"], cwd=repo_root)

    # Push the branch (not the tag) so a pull request can be opened
    branch = get_current_branch(repo_root)
    print(f"\n--- Pushing branch '{branch}' ---")
    run_cmd(["git", "push", "origin", branch], cwd=repo_root)

    print(f"""
Success! Version bumped to v{new_version_str}.

Next steps:
  1. Open a pull request for branch '{branch}' and merge it to master.
  2. After the PR is merged, push the release tag to trigger CI:
       ./scripts/release.sh --push-tag
""")


if __name__ == "__main__":
    main()
