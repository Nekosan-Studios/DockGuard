import logging
import os

import docker

logger = logging.getLogger(__name__)

# Common Docker socket locations to try when DOCKER_HOST is not set
_CANDIDATE_SOCKETS = [
    "/var/run/docker.sock",
    os.path.expanduser("~/.docker/run/docker.sock"),  # Docker Desktop on macOS
    os.path.expanduser("~/.orbstack/run/docker.sock"),  # OrbStack
]


def _connect_to_docker() -> docker.DockerClient:
    """Connect to Docker, trying common socket locations as a fallback."""
    try:
        return docker.from_env()
    except docker.errors.DockerException:
        pass

    for sock_path in _CANDIDATE_SOCKETS:
        if os.path.exists(sock_path):
            try:
                client = docker.DockerClient(base_url=f"unix://{sock_path}")
                client.ping()
                logger.debug("Connected to Docker via %s", sock_path)
                return client
            except Exception:
                continue

    raise docker.errors.DockerException("Could not find a running Docker daemon at any known socket path")


class DockerWatcher:
    def __init__(self):
        try:
            self.client = _connect_to_docker()
        except docker.errors.DockerException as e:
            logger.warning("Could not connect to Docker (is Docker Desktop running?): %s", e)
            self.client = None

    def list_images(self) -> list[dict]:
        if not self.client:
            return []

        running_image_ids = {container.image.id for container in self.client.containers.list()}

        images = []
        for image in self.client.images.list():
            tag = image.tags[0] if image.tags else None
            images.append(
                {
                    "name": tag if tag else "<untagged>",
                    "grype_ref": tag if tag else f"docker:{image.id}",
                    "hash": image.id.replace("sha256:", "")[:12],
                    "config_digest": image.id,  # config digest (sha256:...) for local dedup
                    "running": image.id in running_image_ids,
                }
            )

        return images

    def get_manifest_digest(self, image_name: str) -> str | None:
        """Return the manifest (repo) digest for *image_name* from Docker's RepoDigests.

        This is the sha256 of the manifest — the same value that the registry
        returns as ``Docker-Content-Digest`` — and is therefore comparable with
        the result of ``registry_checker.get_registry_digest()``.

        Returns None if the image is not found or has no recorded RepoDigests
        (e.g. locally-built images that have never been pulled from a registry).
        """
        if not self.client:
            return None
        try:
            image = self.client.images.get(image_name)
            repo_digests = image.attrs.get("RepoDigests", [])
            repo_prefix = image_name.split(":")[0]
            for rd in repo_digests:
                if rd.startswith(repo_prefix):
                    return rd.split("@", 1)[1]
            if repo_digests:
                return repo_digests[0].split("@", 1)[1]
        except Exception as exc:
            logger.debug("Could not resolve manifest digest for %s: %s", image_name, exc)
        return None

    def list_running_containers(self) -> list[dict]:
        """Return one entry per running container (not per image).

        Keys:
            container_name  — Docker container name, leading slash stripped
            image_name      — first tag, or '<untagged>'
            grype_ref       — tag or docker:<config_digest> for untagged images
            hash            — first 12 chars of config digest (no 'sha256:' prefix)
            config_digest   — full sha256:... config digest for local scan dedup
        """
        if not self.client:
            return []

        containers = []
        for container in self.client.containers.list():
            image = container.image
            # Prefer the image ref from Config.Image (what the user actually ran)
            # over image.tags[0], which can pick the wrong tag when multiple tags
            # point to the same digest.
            config_image = container.attrs.get("Config", {}).get("Image", "")
            tag = config_image if config_image else (image.tags[0] if image.tags else None)
            containers.append(
                {
                    "container_name": container.name.lstrip("/"),
                    "image_name": tag if tag else "<untagged>",
                    "grype_ref": tag if tag else f"docker:{image.id}",
                    "hash": image.id.replace("sha256:", "")[:12],
                    "config_digest": image.id,  # config digest (sha256:...) for local scan dedup
                }
            )

        return containers


if __name__ == "__main__":
    watcher = DockerWatcher()
    for image in watcher.list_images():
        print(f"Name:    {image['name']}")
        print(f"Hash:    {image['hash']}")
        print(f"Running: {image['running']}")
        print()
