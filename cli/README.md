# `async-hwi-cli`

This file is generated from `README.md.template`. Edit the template and run `./update-readme.sh`.

## Install

requirements:
 - `libudev-dev`
 - `pkg-config`


`cargo install async-hwi-cli`

## Usage

```shell
$ hwi -h
HWI CLI

Usage: hwi [OPTIONS] <COMMAND>

Commands:
  address
  device
  psbt
  wallet
  state
  bitbox
  persist
  xpub
  help     Print this message or the help of the given subcommand(s)

Options:
      --fingerprint <FINGERPRINT>  default will be the first connected device with the master fingerprint matching
      --network <NETWORK>          default will be the Bitcoin mainnet network [default: bitcoin]
  -o, --output <OUTPUT>            write command output to file instead of stdout
  -h, --help                       Print help
  -V, --version                    Print version
```

```shell
$ hwi address -h
Usage: hwi address [OPTIONS] <COMMAND>

Commands:
  display
  help     Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi address display -h
Usage: hwi address display [OPTIONS]

Options:
  -i, --index <INDEX>                  address index
      --wallet-name <WALLET_NAME>      wallet name
      --wallet-policy <WALLET_POLICY>  wallet policy
      --hmac <HMAC>                    proof of registration, ledger only
      --p2tr <P2TR>                    display a taproot address from path
  -o, --output <OUTPUT>                write command output to file instead of stdout
  -h, --help                           Print help
```

```shell
$ hwi device -h
Usage: hwi device [OPTIONS] <COMMAND>

Commands:
  list
  help  Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi device list -h
Usage: hwi device list [OPTIONS]

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi psbt -h
Usage: hwi psbt [OPTIONS] <COMMAND>

Commands:
  sign  sign psbt from --psbt or --psbt-file
  help  Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi psbt sign -h
sign psbt from --psbt or --psbt-file

Usage: hwi psbt sign [OPTIONS]

Options:
      --psbt <PSBT>                    psbt to sign
      --psbt-file <PSBT_FILE>          read psbt from file
      --wallet-name <WALLET_NAME>      wallet name
      --wallet-policy <WALLET_POLICY>  wallet policy
      --hmac <HMAC>                    proof of registration, ledger only
  -o, --output <OUTPUT>                write command output to file instead of stdout
  -h, --help                           Print help (see more with '--help')
```

```shell
$ hwi wallet -h
Usage: hwi wallet [OPTIONS] <COMMAND>

Commands:
  register       register wallet from persisted state or --name and --policy
  is-registered  check wallet registration from persisted state or wallet name and policy
  help           Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi wallet register -h
register wallet from persisted state or --name and --policy

Usage: hwi wallet register [OPTIONS]

Options:
  -n, --name <NAME>      wallet name
  -p, --policy <POLICY>  wallet policy
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help (see more with '--help')
```

```shell
$ hwi wallet is-registered -h
check wallet registration from persisted state or wallet name and policy

Usage: hwi wallet is-registered [OPTIONS]

Options:
  -n, --name <NAME>      wallet name
  -p, --policy <POLICY>  wallet policy
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help (see more with '--help')
```

```shell
$ hwi bitbox -h
Usage: hwi bitbox [OPTIONS] <COMMAND>

Commands:
  show  show bitbox pairing state
  help  Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi state -h
Usage: hwi state [OPTIONS] <COMMAND>

Commands:
  clear  clear wallet state
  show   show wallet state
  edit   edit wallet state
  rm     remove wallet state field
  help   Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi state edit -h
edit wallet state

Usage: hwi state edit [OPTIONS] <FIELD> <VALUE>

Arguments:
  <FIELD>  state field to edit [possible values: name, descriptor, por]
  <VALUE>  field value

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi state rm -h
remove wallet state field

Usage: hwi state rm [OPTIONS] <FIELD>

Arguments:
  <FIELD>  state field to remove [possible values: name, descriptor, por]

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi persist -h
Usage: hwi persist [OPTIONS] <COMMAND>

Commands:
  enable   enable persistence
  disable  disable persistence
  status   show persistence status
  help     Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi xpub -h
Usage: hwi xpub [OPTIONS] <COMMAND>

Commands:
  get
  help  Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

```shell
$ hwi xpub get -h
Usage: hwi xpub get [OPTIONS] --path <PATH>

Options:
      --path <PATH>      derivation path
  -o, --output <OUTPUT>  write command output to file instead of stdout
  -h, --help             Print help
```

## Persistence

Persistence is disabled by default. Enable it with:

```shell
$ hwi persist enable
```

On Linux, async-hwi stores state under `~/.async-hwi`. On macOS and Windows, it uses the platform config directory.

Wallet state is a JSON object keyed by fingerprint:

```json
{
  "ffd63c8d": {
    "kind": "ledger",
    "name": "Liana",
    "descriptor": "wsh(...)"
  }
}
```

BitBox02 pairing data is stored globally in `bitbox.json` because one BitBox pairing config works for all paired BitBox02 devices.

## Examples

```shell
$ hwi device list
ledger ffd63c8d 2.1.3
```

```shell
$ hwi xpub get --path "m/48'/0'/0'/1'"
[ffd63c8d/48'/0'/0'/1']xpub6E3wdqR3xPHvUKBWwUik5cpy9pMdrdEYVHBxKx7nbT2ZTnzizbNAWe9uuPX4A4nUsamM2Tn9F6ccK5Fmrt6ResBSRWDnb9J8bpi1WKcD158
```

```shell
$ hwi wallet register --name "Liana" --policy "wsh(or_d(multi(2,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*,[de6eb005/48'/1'/0'/2']tpubDFGuYfS2JwiUSEXiQuNGdT3R7WTDhbaE6jbUhgYSSdhmfQcSx7ZntMPPv7nrkvAqjpj3jX9wbhSGMeKVao4qAzhbNyBi7iQmv5xxQk6H6jz/<0;1>/*),and_v(v:pkh([ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*),older(3))))#p9ax3xxp"
4e143a98f46ea585fb8d87a6dd3ca14d689dfbf3d2e9ca1f9618b60cf969c232
```

```shell
$ hwi --network=testnet address display --p2tr="m/86'/1'/0'/0/1
```

```shell
$ hwi psbt sign \
    --wallet-name "Liana" \
    --wallet-policy "wsh(or_d(multi(2,[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<0;1>/*,[de6eb005/48'/1'/0'/2']tpubDFGuYfS2JwiUSEXiQuNGdT3R7WTDhbaE6jbUhgYSSdhmfQcSx7ZntMPPv7nrkvAqjpj3jX9wbhSGMeKVao4qAzhbNyBi7iQmv5xxQk6H6jz/<0;1>/*),and_v(v:pkh([ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N/<2;3>/*),older(3))))#p9ax3xxp" \
    --hmac "4e143a98f46ea585fb8d87a6dd3ca14d689dfbf3d2e9ca1f9618b60cf969c232" \
    --psbt "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
```
