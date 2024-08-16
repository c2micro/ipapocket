# ipapocket

`ipapocket` is a python library for interacting with FreeIPA network protocols. `ipapocket` is focused on providing low-level programmatic access to protocols through a convenient object-oriented API, with which you can construct packets from scratch or parse them from raw data. `ipapocket` also provides several tools as an example of what can be done with this library.

## Why?

Due to lack of [support for FreeIPA](https://github.com/fortra/impacket/pull/1684#issuecomment-1986367074) features in impacket and attempts to make a more user-friendly interface for interacting with kerberos (we plan to add more network protocols in the future).

## For developers

**WARNING: This version of the codebase is under active development so the API may change over time**

Install it via `pip` form GitHub:

```sh
pip install git+https://github.com/c2micro/ipapocket
```

Consider to use a Python virtual environment.

## For pentesters

You can install the tools from the examples using `pipx`:

```sh
pipx install git+https://github.com/c2micro/ipapocket
```

## Examples AKA the pentest tools

`ipp-cve-2024-3183.py` - PoC for CVE-2024-3183. To crack hashes with AES256-SHA1 (etype 18) you can use this ([fork of hashcat](https://github.com/c2micro/hashcat) with mode `32900`.

`ipp-get-tgs.py` - get TGS-REP and save TGS to CCACHE

`ipp-get-tgt.py` - get AS-REP and save TGT to CCACHE

`ipp-user-enum.py` - enumarate users via Kerberos

`ipp-show-ccache.py` - describe credentials in CCACHE
