import os
import shutil
import sys
from datetime import (
    datetime,
)
from logging import (
    Logger,
)
from pathlib import (
    Path,
)
from typing import (
    Any,
    List,
)

import pytest
from _pytest.config import (
    Config,
)
from dotenv import (
    load_dotenv,
)

TEST_DIR = Path(__file__).parent
ROOT_DIR = TEST_DIR.parent
ROOT_PACKAGE = "btctoy"

load_dotenv(TEST_DIR / ".env")  # shared test environment configuration
load_dotenv(ROOT_DIR / ".local" / "test.env")  # private test environment configuration


def pytest_addoption(parser: Any) -> None:  # noqa: ANN401 typing.Any disallowed
    parser.addoption(
        "--force-regen",
        action="store_true",
        default=False,
        help="Force regen regression data files",
    )

    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )


def pytest_collection_modifyitems(config: Config, items: List[Any]) -> None:
    if not config.getoption("--run-slow"):
        skipper = pytest.mark.skip(reason="Only run when --run-slow is given")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skipper)


@pytest.fixture(autouse=True)
def logger(
    request: pytest.FixtureRequest,
) -> Logger:
    from btctoy.utils.logging import (
        LogLevel,
        get_logger,
        init_logging,
    )

    init_logging(LogLevel.DEBUG, "btctoy", "tests")

    return get_logger(f"tests.{request.node.name}")


@pytest.fixture(scope="session")
def session_id() -> str:
    """Offers a unique session id to each test"""
    return datetime.now().strftime("%m%d%H%M%S")


def _win32_longpath(path: Path) -> str:
    """
    Helper function to add the long path prefix for Windows, so that shutil.copytree won't fail
    while working with paths with 255+ chars.
    """
    if sys.platform == "win32":
        # The use of os.path.normpath here is necessary since "the "\\?\" prefix to a path string
        # tells the Windows APIs to disable all string parsing and to send the string that follows
        # it straight to the file system".
        # (See https://docs.microsoft.com/pt-br/windows/desktop/FileIO/naming-a-file)
        return "\\\\?\\" + os.path.normpath(path)
    else:
        return str(path)


@pytest.fixture()
def global_datadir() -> Path:
    return TEST_DIR / "data"


@pytest.fixture()
def original_shared_datadir(request: pytest.FixtureRequest) -> Path:
    original_shared_path = request.path.parent / "data"
    original_shared_path.mkdir(parents=True, exist_ok=True)
    return original_shared_path


@pytest.fixture()
def shared_datadir(original_shared_datadir: Path, tmp_path: Path) -> Path:
    temp_path = tmp_path / "data"
    shutil.copytree(
        _win32_longpath(original_shared_datadir), _win32_longpath(temp_path)
    )
    return temp_path


@pytest.fixture()
def original_datadir(request: pytest.FixtureRequest) -> Path:
    return Path(os.path.splitext(request.module.__file__)[0])


@pytest.fixture()
def datadir(original_datadir: Path, tmp_path: Path) -> Path:
    result = tmp_path / original_datadir.stem
    if original_datadir.is_dir():
        shutil.copytree(_win32_longpath(original_datadir), _win32_longpath(result))
    else:
        result.mkdir()
    return result


if os.getenv("_PYTEST_RAISE", "0") != "0":
    # See https://stackoverflow.com/questions/62419998/how-can-i-get-pytest-to-not-catch-exceptions # noqa
    # Allow to break on exception when debugging in VSCode
    # _PYTEST_RAISE is set to 1 in launch.json for the test launch request.
    @pytest.hookimpl(tryfirst=True)
    def pytest_exception_interact(
        call: Any,  # noqa: ANN401 typing.Any disallowed
    ) -> None:
        raise call.excinfo.value

    @pytest.hookimpl(tryfirst=True)
    def pytest_internalerror(
        excinfo: Any,  # noqa: ANN401 typing.Any disallowed
    ) -> None:
        raise excinfo.value
