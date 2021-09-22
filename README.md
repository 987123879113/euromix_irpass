# euromix_irpass
Dancing Stage Euromix - Internet Challenge password generator

## Usage
```
usage: keygen.py [-h] [--license LICENSE]

optional arguments:
  -h, --help            show this help message and exit
  --license LICENSE, -k LICENSE
                        Machine license key
```

## Building Javascript
Note: pscript is required to build the kicpass.js file required for the webpage.

```
python3 -c "import pscript; pscript.script2js('kicpass.py')"
```
