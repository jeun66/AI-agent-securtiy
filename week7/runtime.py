"""Execute the lab's local file tool against a fixed sandbox directory."""

from contextlib import ExitStack, suppress
import os
from pathlib import Path
import stat
from uuid import uuid4

from week7.scope import Grant


class LocalFileRuntime:
    def __init__(self, sandbox: Path):
        self._sandbox = sandbox

    def run(self, grant: Grant, *, write_content: str | None = None) -> str:
        if grant.action not in {"read_file", "write_file"}:
            raise ValueError("unsupported_tool")
        if grant.action == "write_file" and not isinstance(write_content, str):
            raise ValueError("write_content_required")
        if grant.action == "read_file" and write_content is not None:
            raise ValueError("unexpected_write_content")

        folders = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        components = grant.resource.split("/")
        with ExitStack() as handles:
            directory = os.open(self._sandbox, folders)
            handles.callback(os.close, directory)
            for component in components[:-1]:
                directory = os.open(component, folders, dir_fd=directory)
                handles.callback(os.close, directory)

            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            file = os.open(components[-1], flags, dir_fd=directory)
            handles.callback(os.close, file)
            info = os.fstat(file)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe_file_resource")
            if write_content is not None:
                self._replace_file(directory, components[-1], info, write_content.encode("utf-8"))
                return "written"
            with os.fdopen(file, encoding="utf-8", closefd=False) as stream:
                return stream.read()

    @staticmethod
    def _replace_file(directory: int, name: str, original: os.stat_result, data: bytes) -> None:
        staged = f".w7-write-{uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        handle = os.open(staged, flags, 0o600, dir_fd=directory)
        try:
            with ExitStack() as handles:
                handles.callback(os.close, handle)
                with os.fdopen(handle, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fchmod(stream.fileno(), original.st_mode & 0o777)
                    os.fsync(stream.fileno())
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_nlink) != (original.st_dev, original.st_ino, 1):
                raise ValueError("file_changed_before_write")
            os.replace(staged, name, src_dir_fd=directory, dst_dir_fd=directory)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(staged, dir_fd=directory)
            raise
