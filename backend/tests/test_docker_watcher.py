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


@patch("docker.from_env", side_effect=docker.errors.DockerException("connection refused"))
def test_list_images_docker_unavailable(mock_from_env):
    watcher = DockerWatcher()
    assert watcher.client is None
    assert watcher.list_images() == []
