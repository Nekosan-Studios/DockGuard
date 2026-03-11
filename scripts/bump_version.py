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
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd, cwd=None, check=True):
    """Run a shell command and return its output."""
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


def main():
    parser = argparse.ArgumentParser(description="Bump DockGuard version.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--major", action="store_true", help="Bump major version (X.y.z -> X+1.0.0)")
    group.add_argument("--minor", action="store_true", help="Bump minor version (x.Y.z -> x.Y+1.0)")
    group.add_argument("--patch", action="store_true", help="Bump patch version (x.y.Z -> x.y.Z+1)")
    group.add_argument("--version", type=str, help="Set exact version (e.g., 1.2.3)")
    group.add_argument("--no-commit", action="store_true", help="Skip creating a git commit and tag")

    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

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

    if args.no_commit:
        print("\nSkipping git commit as requested.")
        print("Modified files:")
        for f in modified_files:
            print(f"  - {f.relative_to(repo_root)}")
        return

    print("\n--- Committing changes ---")
    # Commit changes
    for file_path in modified_files:
        run_cmd(["git", "add", str(file_path)], cwd=repo_root)

    commit_msg = f"Bump version to v{new_version_str}"
    print(f"Creating commit: '{commit_msg}'")
    run_cmd(["git", "commit", "-m", commit_msg], cwd=repo_root)

    print(f"Creating tag: v{new_version_str}")
    run_cmd(["git", "tag", f"v{new_version_str}"], cwd=repo_root)

    print("\nSuccess! Version bump complete.")
    print("To push these changes to triggering CI builders:")
    print("  git push origin master")
    print("  git push origin --tags")


if __name__ == "__main__":
    main()
