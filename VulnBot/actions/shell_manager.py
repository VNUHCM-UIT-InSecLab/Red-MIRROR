import os

import paramiko

from actions.local_shell import LocalShell
from actions.remote_shell import RemoteShell
from config.config import Configs


class ShellManager:
    _instance = None
    _ssh_client = None
    _shell = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_shell(self) -> RemoteShell:
        if self._shell is None:
            self._connect()
        return self._shell

    def _connect(self):
        shell_mode = str(os.environ.get("VULNBOT_SHELL_MODE", "auto")).strip().lower()
        if shell_mode == "local":
            self._shell = LocalShell()
            return

        if self._ssh_client is None:
            try:
                self._ssh_client = paramiko.SSHClient()
                self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self._ssh_client.connect(
                    hostname=Configs.basic_config.kali['hostname'],
                    username=Configs.basic_config.kali['username'],
                    password=Configs.basic_config.kali['password'],
                    port=Configs.basic_config.kali['port'],
                    timeout=10,
                )
            except Exception:
                self._ssh_client = None
                self._shell = LocalShell()
                return
        if self._shell is None:
            self._shell = RemoteShell(self._ssh_client.invoke_shell())

    def close(self):
        if self._shell:
            try:
                self._shell.shell.close()
            except:
                pass
            self._shell = None

        if self._ssh_client:
            try:
                self._ssh_client.close()
            except:
                pass
            self._ssh_client = None
