import threading
from unittest.mock import MagicMock, patch

import docker
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


def _make_mock_running_container(
    name: str, image_id: str, tags: list[str], config_image: str | None = None
) -> MagicMock:
    container = MagicMock()
    container.name = name
    container.image.id = image_id
    container.image.tags = tags
    container.attrs = {"Config": {"Image": config_image or (tags[0] if tags else "")}}
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
    assert containers[0]["config_digest"] == image_id


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


@patch("docker.from_env")
def test_list_running_containers_prefers_config_image(mock_from_env):
    """Config.Image (what was passed to docker run) takes priority over image.tags[0]."""
    image_id = "sha256:abcdef123456789000000000000000000000000000000000000000000000000"
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [
        _make_mock_running_container(
            "/my-nginx",
            image_id,
            ["nginx:latest", "localhost:5555/test-nginx:latest"],
            config_image="localhost:5555/test-nginx:latest",
        ),
    ]
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    containers = watcher.list_running_containers()

    assert containers[0]["image_name"] == "localhost:5555/test-nginx:latest"
    assert containers[0]["grype_ref"] == "localhost:5555/test-nginx:latest"


@patch("docker.DockerClient", side_effect=docker.errors.DockerException("connection refused"))
@patch("docker.from_env", side_effect=docker.errors.DockerException("connection refused"))
def test_list_running_containers_docker_unavailable(mock_from_env, mock_client):
    watcher = DockerWatcher()
    assert watcher.list_running_containers() == []


# ---------------------------------------------------------------------------
# get_manifest_digest
# ---------------------------------------------------------------------------


@patch("docker.from_env")
def test_get_manifest_digest_returns_matching_repo_digest(mock_from_env):
    """Should return sha256 of the manifest from RepoDigests matching the image prefix."""
    manifest = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
    mock_image = MagicMock()
    mock_image.attrs = {"RepoDigests": [f"nginx@{manifest}"]}
    mock_client = MagicMock()
    mock_client.images.get.return_value = mock_image
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    assert watcher.get_manifest_digest("nginx:latest") == manifest


@patch("docker.from_env")
def test_get_manifest_digest_falls_back_to_first_repo_digest(mock_from_env):
    """When no RepoDigest prefix matches, return the first one."""
    manifest = "sha256:cccc000000000000000000000000000000000000000000000000000000000000"
    mock_image = MagicMock()
    mock_image.attrs = {"RepoDigests": [f"other-repo@{manifest}"]}
    mock_client = MagicMock()
    mock_client.images.get.return_value = mock_image
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    assert watcher.get_manifest_digest("nginx:latest") == manifest


@patch("docker.from_env")
def test_get_manifest_digest_returns_none_when_no_repo_digests(mock_from_env):
    """Locally-built images with empty RepoDigests should return None."""
    mock_image = MagicMock()
    mock_image.attrs = {"RepoDigests": []}
    mock_client = MagicMock()
    mock_client.images.get.return_value = mock_image
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    assert watcher.get_manifest_digest("myapp:latest") is None


@patch("docker.from_env")
def test_get_manifest_digest_returns_none_on_exception(mock_from_env):
    """If Docker raises (image not found etc.), return None gracefully."""
    mock_client = MagicMock()
    mock_client.images.get.side_effect = Exception("not found")
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    assert watcher.get_manifest_digest("ghost:latest") is None


@patch("docker.from_env")
def test_get_manifest_digest_returns_none_when_no_client(mock_from_env):
    """Return None immediately when Docker is unavailable."""
    watcher = DockerWatcher()
    watcher.client = None
    assert watcher.get_manifest_digest("nginx:latest") is None


# ---------------------------------------------------------------------------
# stream_container_events
# ---------------------------------------------------------------------------


@patch("docker.from_env")
def test_stream_container_events_yields_start_events(mock_from_env):
    event = {"Action": "start", "Type": "container"}
    mock_client = MagicMock()
    mock_client.events.return_value = iter([event])
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    stop_event = threading.Event()
    events = list(watcher.stream_container_events(stop_event))

    assert events == [event]
    mock_client.events.assert_called_once_with(decode=True, filters={"type": "container", "event": "start"})


@patch("docker.from_env")
def test_stream_container_events_stops_on_stop_event(mock_from_env):
    stop_event = threading.Event()
    stop_event.set()  # Set before iteration — each event is checked before yielding

    mock_client = MagicMock()
    mock_client.events.return_value = iter([{"Action": "start"}, {"Action": "start"}])
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    events = list(watcher.stream_container_events(stop_event))

    assert events == []


@patch("docker.from_env")
def test_stream_container_events_no_client(mock_from_env):
    mock_from_env.return_value = MagicMock()

    watcher = DockerWatcher()
    watcher.client = None
    stop_event = threading.Event()

    events = list(watcher.stream_container_events(stop_event))
    assert events == []


@patch("docker.from_env")
def test_stream_container_events_on_docker_exception(mock_from_env):
    mock_client = MagicMock()
    mock_client.events.side_effect = docker.errors.DockerException("connection reset")
    mock_from_env.return_value = mock_client

    watcher = DockerWatcher()
    stop_event = threading.Event()

    # Should not raise — exception is caught and logged as debug
    events = list(watcher.stream_container_events(stop_event))
    assert events == []
