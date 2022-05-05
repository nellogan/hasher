# About
Python implementation of MD5, SHA1, and all SHA2 algorithms (including SHA512/t). SHA3 may be added at a later date. 
This package differs from hashlib in that SHA512/t is available and the user can also hash files by passing the file path directly. Includes a command line interface and unit tests.


### Command line example:
`python -m hasher SHA512/256 "\..\file_path" False`

SHA512/256 is SHA512/t with t set to 256 bits. True/False designates whether "\..\filepath" is a file or a string.
Returns a hexadecimal string.


### Library example:
`import hasher`

`print(hasher.sha512_t("test string",string=True,t=256).hexdigest()))`

`print(hasher.sha384("test string",string=True).hexdigest()))`


### Test example:
change directory to \\..\hasher

`python tests.py`



For SHA512/t, t is generally set to 256 or 224 bits. User may set t
to 1 <= value <= 512 (NIST FIPS 180-4 specifies to not set t to 384 bits).
