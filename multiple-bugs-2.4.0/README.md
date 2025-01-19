# Multiple Bugs in pngcheck 2.4.0

Multiple vulnerabilities found in pngcheck 2.4.0, including:

- Buffer out-of-bounds read in MNG chunks (DISC, DROP, nEED, PAST, SAVE, SEEK)
- Null-pointer dereference in sCAL chunk

## POC Files

- buffer out-of-bounds:
    - [poc-disc.mng](./poc-disc.mng)
    - [poc-drop.mng](./poc-drop.mng)
    - [poc-need.mng](./poc-need.mng)
    - [poc-past.mng](./poc-past.mng)
    - [poc-save.mng](./poc-save.mng)
    - [poc-seek.mng](./poc-seek.mng)
- null-pointer dereference:
    - [poc-scal.png](./poc-scal.png)
- generator script: [poc.py](./poc.py)

## Usage

```
# generate POCs
python poc.py all

# test POCs
pngcheck -v poc-disc.mng
pngcheck poc-drop.mng
pngcheck -v poc-need.mng
pngcheck -f poc-past.mng
pngcheck -v poc-save.mng
pngcheck -v poc-seek.mng
pngcheck -f poc-scal.png
```
