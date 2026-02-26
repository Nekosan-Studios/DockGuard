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


if __name__ == "__main__":
    watcher = DockerWatcher()
    for image in watcher.list_images():
        print(f"Name:    {image['name']}")
        print(f"Hash:    {image['hash']}")
        print(f"Running: {image['running']}")
        print()
