import docker


def list_images():
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        print(f"Error: Could not connect to Docker. Is Docker Desktop running?\nDetails: {e}")
        return []

    running_image_ids = {
        container.image.id
        for container in client.containers.list()
    }

    images = []
    for image in client.images.list():
        tag = image.tags[0] if image.tags else None
        images.append({
            "name": tag if tag else "<untagged>",
            "grype_ref": tag if tag else f"docker:{image.id}",
            "hash": image.id.replace("sha256:", "")[:12],
            "running": image.id in running_image_ids,
        })

    return images


if __name__ == "__main__":
    for image in list_images():
        print(f"Name:    {image['name']}")
        print(f"Hash:    {image['hash']}")
        print(f"Running: {image['running']}")
        print()
