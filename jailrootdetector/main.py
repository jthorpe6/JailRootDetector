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


def string_search(app, strings):
    for string in strings:
        try:
            r_pipe = r2pipe.open(app)
            r_strings = r_pipe.cmd('izzq~+{}'.format(string))
            if r_strings:
                yield r_strings
        except Exception:
            pass

    # /bin/strings if radare2 fails
    sh_strings = sh.strings(app)
    for line in sh_strings:
        for string in strings:
            if string in line:
                yield line


def main():
    args = get_args()

    if args.dex:
        app = args.dex
        from jailrootdetector.detections import root_strings
        strings = root_strings
    elif args.ios:
        app = args.ios
        from jailrootdetector.detections import jailbreak_strings
        strings = jailbreak_strings
    else:
        sys.exit()

    print('\n[+] searching\n')
    search_results = set(string_search(app, strings))
    if search_results:
        print('[+] detection strings found:')
        for string in search_results:
            print('{}'.format(string.strip()))
    else:
        print('[+] no detection strings found in: {}'.format(app))


if __name__ == '__main__':
    main()
