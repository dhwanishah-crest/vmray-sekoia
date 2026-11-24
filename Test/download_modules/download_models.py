"""Models of the Download File action."""

from pydantic import BaseModel, Field, field_validator


class DownloadFileArguments(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        title="URL",
        description="The http:// or https:// address of the file to download, e.g. a zip file. Only public addresses "
        "are allowed.",
    )
    file_name: str = Field(
        default="",
        title="File name",
        description="The name to save the file under. Empty: the name the server gives it, or the last part of the "
        "URL.",
    )
    max_size_mb: int = Field(
        default=50,
        ge=1,
        le=500,
        title="Max size (MB)",
        description="The largest file to accept, in megabytes. A bigger file is dropped and the action fails.",
    )
    timeout: float = Field(
        default=120,
        gt=0,
        le=1800,
        allow_inf_nan=False,
        title="Timeout (s)",
        description="The most time, in seconds, the whole download may take.",
    )
    verify_ssl: bool = Field(
        default=True,
        title="Verify SSL",
        description="Verify the TLS certificate of the server. Turn it off only for a test server with a self-signed "
        "certificate.",
    )

    @field_validator("url", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class FileRef(BaseModel):
    path: str = Field(description="The file's path in the playbook run's storage.")


class DownloadFileResults(BaseModel):
    files: list[FileRef] = Field(
        description='The downloaded file as `[{"path": ...}]`, the shape SentinelOne\'s Get malwares from threat '
        "returns: give it as is to Submit Sample's `files`."
    )
    file_name: str = Field(title="File Name", description="The name the file was saved under.")
    size: int = Field(description="Size of the file in bytes.")
    sha256: str = Field(description="SHA-256 of the file.")
    content_type: str | None = Field(default=None, title="Content Type", description="The server's Content-Type.")
    url: str = Field(description="The address the file came from, after any redirects.")
