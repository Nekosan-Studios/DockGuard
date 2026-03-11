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
                    "image_id": image.id,  # full sha256:... for change detection
                    "running": image.id in running_image_ids,
                }
            )

        return images

    def list_running_containers(self) -> list[dict]:
        """Return one entry per running container (not per image).

        Keys:
            container_name  — Docker container name, leading slash stripped
            image_name      — first tag, or '<untagged>'
            grype_ref       — tag or docker:<image_id> for untagged images
            hash            — first 12 chars of image id (no 'sha256:' prefix)
            image_id        — full sha256:... for change detection / dedup
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
                    "image_id": image.id,
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
