import os
import sys
from flask import Flask, request


app = Flask(__name__)


def read_file(name):
    return open(os.path.join("/tmp", name)).read()


def run_command(command):
    os.system(command)


@app.route("/run")
def run_from_request():
    command = request.args["cmd"]
    os.system(command)
    return "ok"


if __name__ == "__main__":
    print(read_file(os.environ.get("USER_FILE", "default.txt")))
    if len(sys.argv) > 1:
        run_command(sys.argv[1])
