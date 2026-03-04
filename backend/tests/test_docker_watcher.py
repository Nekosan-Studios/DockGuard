from unittest.mock import MagicMock, patch

import docker
import pytest

from backend.docker_watcher import DockerWatcher


def _make_mock_image(image_id: str, tags: list[str]) -> MagicMock:
    image = MagicMock()
    image.id = image_id
    image.tags = tags
    return image


def _make_mock_container(image_id: str) -> MagicMock:
    container = MagicMock()
    container.image.id = image_id
    return container


def _make_mock_running_container(name: str, image_id: str, tags: list[str]) -> MagicMock:
    container = MagicMock()
    container.name = name
    container.image.id = image_id
    container.image.tags = tags
    return container


@patch("docker.from_env")
def test_list_images_tagged(mock_from_env):
    image_id = "sha256:abcdef123456789000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.images.list.return_value = [_make_mock_image(image_id, ["nginx:latest"])]
    mock_client.containers.list.return_value = []
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    images = watcher.list_images()

    assert len(images) == 1
    assert images[0]["name"] == "nginx:latest"
    assert images[0]["grype_ref"] == "nginx:latest"
    assert images[0]["hash"] == "abcdef123456"
    assert images[0]["running"] is False


@patch("docker.from_env")
def test_list_images_untagged(mock_from_env):
    image_id = "sha256:deadbeef000000000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.images.list.return_value = [_make_mock_image(image_id, [])]
    mock_client.containers.list.return_value = []
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    images = watcher.list_images()

    assert images[0]["name"] == "<untagged>"
    assert images[0]["grype_ref"] == f"docker:{image_id}"


@patch("docker.from_env")
def test_list_images_running(mock_from_env):
    image_id = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.images.list.return_value = [_make_mock_image(image_id, ["redis:7"])]
    mock_client.containers.list.return_value = [_make_mock_container(image_id)]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    images = watcher.list_images()

    assert images[0]["running"] is True


@patch("docker.from_env")
def test_list_images_not_running(mock_from_env):
    image_id = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
    other_id = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.images.list.return_value = [_make_mock_image(image_id, ["nginx:latest"])]
    mock_client.containers.list.return_value = [_make_mock_container(other_id)]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    images = watcher.list_images()

    assert images[0]["running"] is False


@patch("docker.DockerClient", side_effect=docker.errors.DockerException("connection refused"))
@patch("docker.from_env", side_effect=docker.errors.DockerException("connection refused"))
def test_list_images_docker_unavailable(mock_from_env, mock_client):
    watcher = DockerWatcher()
    assert watcher.client is None
    assert watcher.list_images() == []


# ---------------------------------------------------------------------------
# list_running_containers
# ---------------------------------------------------------------------------

@patch("docker.from_env")
def test_list_running_containers_tagged(mock_from_env):
    image_id = "sha256:abcdef123456789000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [
        _make_mock_running_container("/my-nginx", image_id, ["nginx:latest"]),
    ]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    containers = watcher.list_running_containers()

    assert len(containers) == 1
    assert containers[0]["container_name"] == "my-nginx"
    assert containers[0]["image_name"] == "nginx:latest"
    assert containers[0]["grype_ref"] == "nginx:latest"
    assert containers[0]["hash"] == "abcdef123456"
    assert containers[0]["image_id"] == image_id


@patch("docker.from_env")
def test_list_running_containers_untagged(mock_from_env):
    image_id = "sha256:deadbeef000000000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [
        _make_mock_running_container("/my-container", image_id, []),
    ]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    containers = watcher.list_running_containers()

    assert containers[0]["image_name"] == "<untagged>"
    assert containers[0]["grype_ref"] == f"docker:{image_id}"


@patch("docker.from_env")
def test_list_running_containers_multiple_same_image(mock_from_env):
    """Two containers running the same image each appear as separate entries."""
    image_id = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [
        _make_mock_running_container("/web-1", image_id, ["nginx:latest"]),
        _make_mock_running_container("/web-2", image_id, ["nginx:latest"]),
    ]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    containers = watcher.list_running_containers()

    assert len(containers) == 2
    names = {c["container_name"] for c in containers}
    assert names == {"web-1", "web-2"}


@patch("docker.from_env")
def test_list_running_containers_strips_leading_slash(mock_from_env):
    image_id = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [
        _make_mock_running_container("/my-app", image_id, ["myapp:1.0"]),
    ]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    containers = watcher.list_running_containers()

    assert containers[0]["container_name"] == "my-app"


@patch("docker.DockerClient", side_effect=docker.errors.DockerException("connection refused"))
@patch("docker.from_env", side_effect=docker.errors.DockerException("connection refused"))
def test_list_running_containers_docker_unavailable(mock_from_env, mock_client):
    watcher = DockerWatcher()
    assert watcher.list_running_containers() == []
