# Vulns in pngcheck 3.0.0

Two Buffer out-of-bounds read found in pngcheck 3.0.0.

- PPLT chunk: when `last_idx` < `first_idx`, `bytes_left` increases instead of decreases
- LOOP chunk: buffer overflow due to unchecked iterations count

## POC Files

- poc images:
    - [poc-loop.mng](./poc-loop.mng)
    - [poc-pplt.mng](./poc-pplt.mng)
- generator script: [poc.py](./poc.py)

## Usage

```
# generate POCs
python poc.py all

# test POCs
pngcheck -v poc-loop.mng
pngcheck poc-pplt.mng
```
