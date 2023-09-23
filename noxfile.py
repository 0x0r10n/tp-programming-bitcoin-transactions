import logging
import os
import tempfile
from contextlib import (
    contextmanager,
)
from functools import (
    reduce,
)
from pathlib import (
    Path,
)
from typing import (
    Any,
    Generator,
    List,
)

import nox
from nox.sessions import (
    Session,
)
from setuptools import (
    find_namespace_packages,
    find_packages,
)

nox.options.sessions = "lint", "mypy", "safety", "test"

SOURCE_LOCATIONS = ["src", "tests", "noxfile.py"]

logger = logging.getLogger(__name__)  # type: ignore


@nox.session
def test(session: Session) -> None:
    args = session.posargs or [
        "--cov-fail-under",
        "10",
        "-m",
        "not e2e",
    ]
    session.run(
        "poetry",
        "install",
        "--with",
        "dev",
        external=True,
    )
    session.run("pytest", *args)


@nox.session
def lint(session: Session) -> None:
    args = session.posargs or SOURCE_LOCATIONS
    session.run(
        "poetry",
        "install",
        "--with",
        "dev",
        external=True,
    )
    session.run("flake8", *args)


@nox.session
def safety(session: Session) -> None:
    with temporary_file() as requirements:
        export_poetry_requirements(session, requirements)
        session.install("safety")
        session.run("safety", "check", f"--file={requirements}", "--full-report")


@nox.session
def mypy(session: Session) -> None:
    args = session.posargs or SOURCE_LOCATIONS

    # Install the whole project in virutal env for running mypy, to ensure we have
    # library stubs of dependencies.
    # It allows to limit the use of 'ignore_missing_imports' in mypy.ini
    session.run("poetry", "install", external=True)

    # Unfortunately, mypy may not work as expected with namespace packages
    # We enforce the presence of __init__.py file in all subpackages to avoid any issue
    with temporary_init_files_in_namespace_packages(args):
        session.run("mypy", "--install-types", "--non-interactive")
        session.run("mypy", *args)


@contextmanager
def temporary_file() -> Generator[str, None, None]:
    # On windows we cannot use tempfile.NamedTemporaryFile() directly because
    # the file cannot be written while still open
    tmpf = tempfile.NamedTemporaryFile(delete=False)
    tmpf.close()
    try:
        yield tmpf.name
    finally:
        os.unlink(tmpf.name)


def export_poetry_requirements(
    session: Session,
    file_name: str,
    groups: str = "dev",
) -> None:
    session.run(
        "poetry",
        "export",
        "--with",
        groups,
        "--format=requirements.txt",
        f"--output={file_name}",
        external=True,
    )


def install_with_constraints(
    session: Session,
    *args: str,
    **kwargs: Any,  # noqa: ANN401 typing.Any disallowed
) -> None:
    with temporary_file() as requirements:
        export_poetry_requirements(session, requirements)
        session.install(f"--constraint={requirements}", *args, **kwargs)


@contextmanager
def temporary_init_files_in_namespace_packages(
    source_locations: List[str],
) -> Generator[List[Path], None, None]:
    """
    Convert all namespace packages to packages in specified source locations.
    Returns the list of __init__.py files created that way.
    """
    init_files = []
    for source_location in source_locations:
        if not Path(source_location).is_dir():
            continue

        root_dir = source_location
        found_packages = find_packages(root_dir)
        found_ns_packages = find_namespace_packages(root_dir)
        for package in set(found_ns_packages) - set(found_packages):
            subdir = reduce(
                lambda parent_dir, subdir: parent_dir / subdir,
                package.split("."),
                Path(root_dir),
            )
            init_file = subdir / "__init__.py"
            if not Path(init_file).exists():
                init_files.append(init_file)

    for init_file in init_files:
        with open(init_file, "w") as init_file_io:
            logger.info(f"Creating temporary empty init file {init_file}")
            init_file_io.write("# empty init file for mypy\n")

    # Count total number of python files so we can check if mypy process the same amount
    logger.info(
        f"Total number of python files: {_count_python_files(source_locations)}"
    )

    try:
        yield init_files
    finally:
        for init_file in init_files:
            logger.info(f"Removing temporary empty init file {init_file}")
            init_file.unlink()


def _count_python_files(
    source_locations: List[str],
) -> int:
    python_file_count = 0
    for source_location in source_locations:
        path = Path(source_location)
        if path.is_file() and path.suffix == ".py":
            python_file_count += 1
        elif path.is_dir():
            for _root, _dirs, files in os.walk(source_location):
                for f in files:
                    if Path(f).suffix == ".py":
                        python_file_count += 1
    return python_file_count
