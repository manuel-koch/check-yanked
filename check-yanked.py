#!/usr/bin/env python3
import argparse
import base64
import configparser
import datetime
import hashlib
import json
import logging
import subprocess
import sys
import tempfile
from datetime import timedelta, time
from pathlib import Path
from typing import List, Tuple, Optional
import socket
import ssl
import urllib.parse
import platform

logger = logging.getLogger("check-yanked")

METHOD_PIP_FREEZE = "pipfreeze"
METHOD_PKG_RESOURCES = "pgkresources"

CACHE_DIR = Path(tempfile.gettempdir()) / "check-yanked"
MAX_CACHE_AGE = timedelta(hours=6).total_seconds()


def http_get(
    url: str,
    port: Optional[int] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Optional[bytes]:
    """
    Performs an HTTP GET request using standard Python library.

    :param url: The URL to request (e.g., "http://www.example.com/path?query=value").
    :param port: The port to use (e.g. 80 or 443).
    :returns The response body or None in case of error.
    """
    sock = None
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        path = parsed_url.path or "/"

        auth = ""
        if username and password:
            basic_auth = base64.b64encode(f"{username}:{password}".encode("utf8"))
            auth = f"Authorization: Basic {basic_auth.decode('utf8')}\r\n"

        payload = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\n{auth}Connection: close\r\n\r\n".encode(
            "utf-8"
        )

        def send_and_receive(s) -> bytes:
            """
            Send the request to the server and read all data.
            This may include chunked response data!
            """
            s.sendall(payload)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data

        if parsed_url.scheme == "https":
            # Create SSL socket
            port = port or 443
            # Create a socket connection with the server using SSL/TLS
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Send GET request to the server
                    # Read response from server
                    response = send_and_receive(ssock)
        else:
            port = port or 80
            try:
                sock = None
                sock = socket.create_connection((hostname, port))
                # Send GET request to the server
                # Read response from server
                response = send_and_receive(sock)
            finally:
                if sock:
                    sock.close()

        # Split into header and body
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            logger.warning("Malformed response, can't determine header end")
            return None

        header_bytes = response[:header_end]
        body_bytes = response[header_end + 4 :]

        try:
            status_line = header_bytes.split(b"\r\n")[0].decode("utf-8")
            status_code = int(status_line.split(" ")[1])

            headers = {}
            for header in header_bytes.split(b"\r\n"):
                if b":" in header:
                    key, value = header.split(b":", 1)
                    headers[key.strip().decode("utf8").lower()] = value.strip().decode(
                        "utf8"
                    )

            # Need to remove the chunk indicators in the received response
            transfer_encoding = headers.get("transfer-encoding", "").lower()
            if transfer_encoding == "chunked":
                chunked_body_bytes = body_bytes
                body_bytes = b""
                while chunked_body_bytes:
                    chunk_size, chunk_data = chunked_body_bytes.split(
                        b"\r\n", maxsplit=1
                    )
                    chunk_size = int(chunk_size, 16)
                    chunked_body_bytes = chunk_data[chunk_size + 2 :]
                    body_bytes += chunk_data[:chunk_size]

            # Only return body for successful HTTP responses
            if 200 <= status_code < 300:
                return body_bytes

            else:
                logger.error(f"Server {hostname} returned status code {status_code}")
                return None
        except Exception:
            logger.exception("Error processing headers")
            return None

    except socket.gaierror:
        logger.exception("Socket error")
        return None
    except ssl.SSLError:
        logger.exception("SSL error")
        return None
    except Exception:
        logger.exception("Unknown error")
        return None


def get_installed_packages_via_pkg_resources() -> List[Tuple[str, str]]:
    logger.info("Getting installed packages via pkg_resources")
    try:
        import pkg_resources
    except:
        logger.error(
            "Could not import 'pkg_resources', please install it manually via `pip install --upgrade setuptools`"
        )
        return []

    # To check all installed packages (adapt as needed)
    packages = []
    for package in pkg_resources.working_set:
        if package.project_name != "check-yanked":
            packages.append((package.project_name, package.version))
    return packages


def get_installed_packages_via_pip_freeze() -> List[Tuple[str, str]]:
    logger.info("Getting installed packages via pip freeze")
    packages = []
    freeze_output = subprocess.check_output(["pip3", "freeze"], encoding="utf-8")
    for line in freeze_output.split("\n"):
        if not line.strip():
            continue
        package_name, package_version = line.split("==", maxsplit=1)
        if package_name == "check-yanked":
            continue
        packages.append((package_name, package_version))
    return packages


def check_yanked(
    package: str,
    version: str,
    index_url: str,
    index_username: Optional[str] = None,
    index_password: Optional[str] = None,
    cached: bool = False,
):
    try:
        hasher = hashlib.sha256()
        hasher.update(f"{package}{index_url}".encode("utf8"))
        cache_path = CACHE_DIR / f"{package}-{hasher.hexdigest()}.json"
        if (
            cached
            and cache_path.exists()
            and cache_path.stat().st_mtime + MAX_CACHE_AGE
            > datetime.datetime.now().timestamp()
        ):
            logger.debug(
                f"Loading cached PyPi index for package {package} from {cache_path}"
            )
            index_data = json.loads(cache_path.read_bytes())
        else:
            index_json_url = urllib.parse.urljoin(index_url, f"pypi/{package}/json")
            response = http_get(
                index_json_url, username=index_username, password=index_password
            )
            index_data = json.loads(response)
            if cached:
                cache_path.parent.mkdir(exist_ok=True, parents=True)
                cache_path.write_bytes(response)
                logger.debug(
                    f"Caching PyPi index for package {package} to {cache_path}"
                )
        if not index_data:
            logger.warning(f"No PyPi details for package {package} found")
            return
        releases = index_data.get("releases", {})
        version_packages = releases.get(version, [])
        any_package_yanked = False
        for version_package in version_packages:
            package_type = version_package.get("packagetype", "?")
            python_version = version_package.get("python_version", "?")
            filename = version_package.get("filename", "?")
            yanked = version_package.get("yanked", False)
            yanked_reason = version_package.get("yanked_reason", "")
            if yanked:
                any_package_yanked = True
                logger.info(
                    f"Package {package} in version {version} ({package_type}, {python_version}, {filename}) is marked as yanked: {yanked_reason}"
                )
        if not any_package_yanked:
            logger.info(f"Package {package} in version {version} looks ok")
    except Exception:
        logger.exception(f"Error fetching PyPi data for {package}")


def get_index_url_from_pip_config(config_path: str | Path) -> Tuple[str, str, str]:
    """
    Get PyPi index URL from pip config.

    :param config_path: Load pip config from given path
    :return: Tuple of URL, username, password to access pypi index
    """
    config = configparser.ConfigParser()
    config.read(config_path)

    # Find the index-url (PyPI repository URL)
    index_url = None
    for section in config.sections():
        if "index-url" in config[section]:
            index_url = config[section]["index-url"]
            break
    if not index_url:
        raise Exception(f"No index-url found in pip configuration at {config_path}")

    parsed_index_url = urllib.parse.urlparse(index_url)
    index_url = f"{parsed_index_url.scheme}://{parsed_index_url.hostname}{':' if parsed_index_url.port else ''}{parsed_index_url.port if parsed_index_url.port else ''}{parsed_index_url.path}"

    # Get authentication details (if present)
    username = parsed_index_url.username
    password = parsed_index_url.password
    for section in config.sections():
        if "username" in config[section]:
            username = config[section]["username"]
        if "password" in config[section]:
            password = config[section]["password"]

    return index_url, username, password


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="check-yanked",
        description="Identify python packages that are marked as yanked",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--cache", action="store_true", default=True)
    parser.add_argument("--no-cache", action="store_false", dest="cache")
    parser.add_argument(
        "-m",
        "--method",
        default=METHOD_PIP_FREEZE,
        choices=[METHOD_PIP_FREEZE, METHOD_PKG_RESOURCES],
        help="Select method to get installed packages",
    )
    parser.add_argument(
        "--pip-config-path",
        default="",
        help="Use pip configuration from given path",
    )
    args = parser.parse_args()
    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s [%(levelname)s] PID<%(process)d> %(name)s: %(message)s"
        if args.verbose
        else "%(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    logger.info(
        f"Analysing packages in {platform.python_implementation()} {platform.python_version()} {sys.executable}"
    )

    if args.method == METHOD_PIP_FREEZE:
        installed_package_versions = get_installed_packages_via_pip_freeze()
    elif args.method == METHOD_PKG_RESOURCES:
        installed_package_versions = get_installed_packages_via_pkg_resources()
    else:
        logger.error(f"Unknown method: {args.method}")
        sys.exit(1)

    index_url = "https://pypi.org/pypi"
    index_username, index_password = None, None

    if args.pip_config_path:
        index_url, index_username, index_password = get_index_url_from_pip_config(
            args.pip_config_path
        )

    logger.info(f"Using PyPi index at {urllib.parse.urlparse(index_url).hostname}")

    for package, version in installed_package_versions:
        check_yanked(
            package=package,
            version=version,
            index_url=index_url,
            index_username=index_username,
            index_password=index_password,
            cached=args.cache,
        )
