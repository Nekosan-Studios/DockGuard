import logging

import docker

logger = logging.getLogger(__name__)


class DockerWatcher:

    def __init__(self):
        try:
            self.client = docker.from_env()
        except docker.errors.DockerException as e:
            logger.warning("Could not connect to Docker (is Docker Desktop running?): %s", e)
            self.client = None

    def list_images(self) -> list[dict]:
        if not self.client:
            return []

        running_image_ids = {
            container.image.id
            for container in self.client.containers.list()
        }

        images = []
        for image in self.client.images.list():
            tag = image.tags[0] if image.tags else None
            images.append({
                "name": tag if tag else "<untagged>",
                "grype_ref": tag if tag else f"docker:{image.id}",
                "hash": image.id.replace("sha256:", "")[:12],
                "image_id": image.id,  # full sha256:... for change detection
                "running": image.id in running_image_ids,
            })

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
            tag = image.tags[0] if image.tags else None
            containers.append({
                "container_name": container.name.lstrip("/"),
                "image_name": tag if tag else "<untagged>",
                "grype_ref": tag if tag else f"docker:{image.id}",
                "hash": image.id.replace("sha256:", "")[:12],
                "image_id": image.id,
            })

        return containers


if __name__ == "__main__":
    watcher = DockerWatcher()
    for image in watcher.list_images():
        print(f"Name:    {image['name']}")
        print(f"Hash:    {image['hash']}")
        print(f"Running: {image['running']}")
        print()
