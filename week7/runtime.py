"""Execute the lab's local file tool against a fixed sandbox directory."""

from contextlib import ExitStack
import os
from pathlib import Path
import stat

from week7.scope import Grant


class LocalFileRuntime:
    def __init__(self, sandbox: Path):
        self._sandbox = sandbox

    def run(self, grant: Grant) -> str:
        if grant.action != "read_file":
            raise ValueError("unsupported_tool")

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
            with os.fdopen(file, encoding="utf-8", closefd=False) as stream:
                return stream.read()
