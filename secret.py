#!/usr/bin/env python3
from difflib import Differ
from pathlib import Path

import curses
import io
import json as json_
import os
import qrcode
import re
import requests
import shutil
import signal
import subprocess
import sys
import time
from tempfile import TemporaryDirectory
from typing import Optional
from urllib.parse import urlencode

from clide.ansi import abort, info, okay
from clide.prompt import proceed, prompt
from shellby import bash
from tooler import Tooler
from lib.password import Store

tooler = Tooler()


@tooler.command
def fs(path: Optional[str] = None, *, name: Optional[str] = None, create: bool = False):
    if path is None:
        path = Path("~/personal/encrypted").expanduser()
        assert name is None
    else:
        path = Path(path)
        if name is None:
            name = path.name

    if create:
        assert not path.exists()
    else:
        assert path.is_dir()

    password = Store.get_fs_password(name=name).encode("ascii")

    if create:
        path.mkdir()
        proc = subprocess.Popen(
            ["gocryptfs", "-init", path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        proc.stdin.write(password)
        proc.stdin.close()
        proc.wait()
        assert proc.returncode == 0

    with TemporaryDirectory() as tmpdir:
        proc = subprocess.Popen(
            ["gocryptfs", "-fg", path, tmpdir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        proc.stdin.write(password)
        proc.stdin.close()
        password = None

        try:
            output = b""
            while True:
                output += proc.stdout.read(1)
                if b"Filesystem mounted" in output:
                    okay(f"Mounted: {tmpdir}")
                    signal.sigwait([signal.SIGINT])
                    break
        except KeyboardInterrupt:
            pass
        finally:
            proc.kill()
            proc.wait()
            # unmount
            bash(
                ["fusermount", "-u", tmpdir],
                display=False,
                quiet=True,
            )
            okay("Unmounted filesystem")


@tooler.command
def shell():
    "Spawns a shell with the database unlocked"
    store = Store.unlock()
    (key, value) = store.to_env()
    os.putenv(key, value)
    os.execv("/bin/bash", ["bash"])


@tooler.command(name="list")
def list_cmd():
    store = Store.unlock()

    db = store.load()
    for key in db.keys():
        print(key)
    if not db:
        print("< database empty >")


@tooler.command()
def write_many():
    store = Store.unlock()
    db = store.load()

    print("Please provide a { key: {entry} } list of secrets")
    secrets = json_.load(sys.stdin)
    for key, value in secrets.items():
        assert type(value) is dict
        if key in db:
            if not proceed(
                f"Entry {json_.dumps(key)} already exists in database, overwrite it?"
            ):
                abort("Cancelling write")
        db[key] = value
    store.write(db)
    okay("Database updated.")


@tooler.command()
def write(name: str, *, json=False):
    store = Store.unlock()
    db = store.load()

    if name in db:
        if not proceed("Entry already exists in database, overwrite it?"):
            abort("Cancelling write")

    if json:
        print("Please enter JSON data:")
        entry = json_.load(sys.stdin)
    else:
        password = prompt("Please enter the password: ")
        entry = {"password": password}

    db[name] = store.encrypt(name, entry)
    store.write(db)
    okay("Database updated.")


@tooler.command()
def read(name: str):
    store = Store.unlock()
    db = store.load()

    if not name in db:
        abort("Could not find %s in database" % json_.dumps(name))

    data = store.decrypt(
        name=name, nonce=db[name]["nonce"], payload=db[name]["payload"]
    )
    print(json_.dumps(data))


@tooler.command()
def qr(name: str):
    store = Store.unlock()
    db = store.load()

    if not name in db:
        abort("Could not find %s in database" % json_.dumps(name))

    data = store.decrypt(
        name=name, nonce=db[name]["nonce"], payload=db[name]["payload"]
    )
    print(json_.dumps(data))

    secret = None
    for key in ("secret", "password", "code", "key"):
        if secret is None:
            secret = data.get(key)

    if not secret:
        abort("Could not find secret in data")

    twofac_name = re.sub(r"^twofac/", "", name)
    url = "otpauth://totp/%s?" % twofac_name + urlencode(
        {
            "issuer": name,
            "secret": secret.replace(" ", ""),
        }
    )
    qr = qrcode.QRCode()
    print(url)
    qr.add_data(url)
    qr.print_ascii(out=sys.stderr, tty=True)


if __name__ == "__main__":
    tooler.main()
