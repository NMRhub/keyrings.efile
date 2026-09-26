"""Command line interface to manage passwords stored by keyrings.efile"""
import argparse
import logging
import sys

from keyrings.efile import EncryptedFile, kef_logger, __version__


def _list(ef: EncryptedFile, args: argparse.Namespace) -> int:
    entries = ef.list_entries()
    if not entries:
        print("No stored entries")
        return 0
    width = max(len(service) for service, _ in entries)
    width = max(width, len('SERVICE'))
    print(f"{'SERVICE':<{width}}  USER")
    for service, user in entries:
        print(f"{service:<{width}}  {user}")
    return 0


def _show(ef: EncryptedFile, args: argparse.Namespace) -> int:
    password = ef.get_password(args.service, args.user)
    if password is None:
        print(f"No password stored for service {args.service} user {args.user}", file=sys.stderr)
        return 1
    print(password)
    return 0


def _delete(ef: EncryptedFile, args: argparse.Namespace) -> int:
    if ef.get_password(args.service, args.user) is None:
        print(f"No password stored for service {args.service} user {args.user}", file=sys.stderr)
        return 1
    ef.delete_password(args.service, args.user)
    print(f"Deleted service {args.service} user {args.user}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='keyrings-efile',
                                     description="Manage passwords stored by keyrings.efile",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-l', '--loglevel', default='WARN', help="Python logging level")
    parser.add_argument('--version', action='version', version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest='command', required=True)

    subparsers.add_parser('list', help="list stored services and users").set_defaults(func=_list)
    for name, func, help_text in (('show', _show, "display password for service and user"),
                                  ('delete', _delete, "delete entry for service and user")):
        sp = subparsers.add_parser(name, help=help_text)
        sp.add_argument('service', help="service name")
        sp.add_argument('user', help="user name")
        sp.set_defaults(func=func)

    args = parser.parse_args(argv)
    logging.basicConfig()
    kef_logger.setLevel(getattr(logging, args.loglevel.upper()))
    return args.func(EncryptedFile(), args)


if __name__ == "__main__":
    sys.exit(main())
