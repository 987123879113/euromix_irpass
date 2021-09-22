import argparse
import datetime
import random
import sys

import kicpass


def seed_checker(minval, maxval):
    def seed_range_checker(arg):
        try:
            f = int(arg)

        except ValueError:
            raise argparse.ArgumentTypeError("must be an integer")

        if f < minval or f > maxval:
            raise argparse.ArgumentTypeError("must be in range [" + str(minval) + " .. " + str(maxval)+"]")

        return f

    return seed_range_checker


def date_checker(val):
    try:
        f = int(val)

    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if not rtcpass.verify_date(f):
        raise argparse.ArgumentTypeError("not a valid date")

    return f

def get_current_date():
    now = datetime.datetime.now()
    date = "%02d%02d%02d" % ((now.year % 100), now.month, now.day)
    return int(date)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--license', '-k', help='Machine license key', default="BWRBQE9132DXTKCRPRN64")

    args = parser.parse_args()

    password = kicpass.generate_password(args.license)
    print(password)
