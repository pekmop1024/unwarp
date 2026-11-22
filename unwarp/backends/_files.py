"""Stage related profile files in their destination before publishing them."""

import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path


@contextmanager
def locked_directory(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def existing_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(mode):
        raise ValueError(f'expected a regular file at {path}')
    return True


def read_profile(path: Path) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, encoding='utf-8', newline='') as source:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f'expected a regular file at {path}')
        return source.read()


@dataclass(frozen=True)
class Artifact:
    content: bytes = field(repr=False)
    mode: int = 0o600
    group: int | None = None


def publish(directory: Path, changes: dict[Path, Artifact | None]) -> None:
    """Install a batch under the directory lock, restoring previous files on failure."""
    if not changes:
        return
    with tempfile.TemporaryDirectory(prefix='.unwarp-', dir=directory) as staging:
        stage = Path(staging)
        backups = {}
        for path, artifact in changes.items():
            if existing_file(path):
                backup = stage / (path.name + '.old')
                os.link(path, backup, follow_symlinks=False)
                backups[path] = backup
            if artifact is not None:
                with (stage / path.name).open('xb') as output:
                    output.write(artifact.content)
                    if artifact.group is not None:
                        os.fchown(output.fileno(), -1, artifact.group)
                    os.fchmod(output.fileno(), artifact.mode)
        installed = []
        try:
            for path, artifact in changes.items():
                if artifact is None:
                    path.unlink(missing_ok=True)
                elif path in backups:
                    os.replace(stage / path.name, path)
                else:
                    os.link(stage / path.name, path)
                installed.append(path)
        except BaseException:
            for path in reversed(installed):
                if path in backups:
                    os.replace(backups[path], path)
                else:
                    path.unlink(missing_ok=True)
            raise
