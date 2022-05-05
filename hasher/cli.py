from .md5 import md5
from .sha1 import sha1
from .sha224 import sha224
from .sha256 import sha256
from .sha384 import sha384
from .sha512 import sha512
from .sha512_t import sha512_t
import sys


def main():
    # First arg is not given by user.
    if len(sys.argv) != 4:
        print('ERROR')
        print('3 args and only 3 args must be entered. '
              '1st arg: hash function. '
              '2nd arg: file_name/string to be hashed. '
              '3rd arg: string=True/False.')
        print(sys.argv)
        exit()
    args = {}
    for k, v in read_args().items():
        args[k] = v
    result = hash_file(args['hash_function'], args['file'], args['string'])
    print(result)


def read_args():
    return {
        'hash_function': sys.argv[1],
        'file': sys.argv[2],
        'string': sys.argv[3]
    }


# Returns output as hexadecimal string.
def hash_file(hash_function: str, file: str, string: bool):
    function = {
        'md5': md5,
        'sha1': sha1,
        'sha224': sha224,
        'sha256': sha256,
        'sha384': sha384,
        'sha512': sha512,
        'sha512/': sha512_t
    }
    if 'sha512/' in hash_function:
        t = int(hash_function[7:10])
        hash_value = function['sha512/'](file, string, t=t).hexdigest()
    else:
        hash_value = function[hash_function](file, string).hexdigest()
    return hash_value
