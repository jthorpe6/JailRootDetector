import sys
import argparse
import r2pipe
import sh


def get_args():
    parser = argparse.ArgumentParser(description='[+] root & jailbreak detection')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--dex', help='path to android dex file')
    group.add_argument('--ios', help='path to extracted payload binary')
    return parser.parse_args()


def string_search(app, string):
    r_pipe = r2pipe.open(app)
    r_strings = r_pipe.cmd('izzq~+{}'.format(string))
    if r_strings:
        return r_strings

    # /bin/strings if radare2 fails
    sh_strings = sh.strings(app)
    for line in sh_strings:
        if string in line:
            return line

    return False


def main():
    args = get_args()

    if args.dex:
        app = args.dex
        try:
            strings = open('roots.txt', 'r')
        except FileNotFoundError:
            print('[!] did not find a file called "roots.txt"')
            sys.exit()
    elif args.ios:
        app = args.ios
        try:
            strings = open('jailbreaks.txt', 'r')
        except FileNotFoundError:
            print('[!] did not find a file called "jailbreaks.txt"')
    else:
        sys.exit()

    for string in strings:
        search_em = string_search(app, string)
        if search_em:
            print('[+] "{}" detected in {}'.format(string.strip(), app))
            print('{}\n'.format(search_em))

    strings.close()


if __name__ == '__main__':
    main()