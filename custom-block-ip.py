#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import subprocess
import shutil
import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath

if os.name == "nt":
    LOG_FILE = (
        "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
    )
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(
            PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response") :]))
        )
        log_file.write(
            str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
            + " "
            + ar_name_posix
            + ": "
            + msg
            + "\n"
        )


def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON has failed, invalid input format")
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], "Not valid command: " + command)

    return message


def send_keys_and_check_message(argv, keys):

    # build and send message with keys
    keys_msg = json.dumps(
        {
            "version": 1,
            "origin": {"name": argv[0], "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": keys},
        }
    )

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON has failed, invalid input format")
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):

    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:

        """Start Custom Key
        At this point, it is necessary to select the keys from the alert and add them into the keys array.
        """

        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]

        src_ip = alert["data"]["srcip"]
        iptables_path = shutil.which("iptables") or "/sbin/iptables"

        try:
            cmd = [
                "sudo",
                iptables_path,
                "-I",
                "INPUT",
                "-s",
                src_ip,
                "-j",
                "DROP",
            ]
            proc = subprocess.run(cmd)

            write_debug_file(argv[0], f"[CMD EXECUTADO] {' '.join(cmd)}")
            write_debug_file(
                argv[0],
                f"[RETORNO] rc={proc.returncode}, stdout={proc.stdout.strip()}, stderr={proc.stderr.strip()}",
            )

            if proc.returncode == 0:
                write_debug_file(
                    argv[0], f"[SUCESSO] IP {src_ip} bloqueado no firewall."
                )
            else:
                write_debug_file(argv[0], f"[ERRO] Falha ao bloquear {src_ip}")
        except Exception as e:
            write_debug_file(argv[0], f"[EXCEPTION] {e}")

        write_debug_file(argv[0], f"[FIM DA EXECUÇÃO COMANDO custom-block-ip.py]")
        """ End Custom Key """

        action = send_keys_and_check_message(argv, keys)

        # if necessary, abort execution
        if action != CONTINUE_COMMAND:

            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        """ Start Custom Action Add """

        """ End Custom Action Add """

    elif msg.command == DELETE_COMMAND:

        """Start Custom Action Delete"""

        os.remove("ar-test-result.txt")

        """ End Custom Action Delete """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
