# 1Password Plugin for age

`age-plugin-pwmanager` is a plugin for age clients like [age](https://github.com/FiloSottile/age/)
and [rage](https://github.com/str4d/rage) which allows you to use SSH keys stored inside password managers.
Currently 1Password and bitwarden are supported.

## Differences with `age-plugin-op`

- Uses SSH public keys (e.g. `ssh-ed25519 AAAAC3N...`) as `age` recipients
- Does not require the plugin or 1Password for encryption
- Supports decryption without identity files (`age --decrypt -j 1p`)

## Requirements


- An age client such as [age](https://github.com/FiloSottile/age/) or [rage](https://github.com/str4d/rage)
- The CLI for your password manager
    - [1Password CLI](https://1password.com/downloads/command-line/)
    - [Bitwden CLI]( https://bitwarden.com/help/cli/)

## Testing

To use `age-plugin-pwmanager` without installation, you can run `age` through Nix to provide the plugin:

```
$ nix run github:Enzime/age-plugin-pwmanager#age
```

The actual plugin is available as:

```
$ nix run github:Enzime/age-plugin-pwmanager
```

Or you can enter a shell environment that provides both `age` and `age-plugin-*`
for all supported backends:

```
$ nix shell github:Enzime/age-plugin-pwmanager
```

## Installation

You can build the `age-plugin-*` binaries using Nix:

```sh
$ nix build github:Enzime/age-plugin-1p
$ nix build github:Enzime/age-plugin-bitwarden
```

Which can then be copied or symlinked to your `PATH`


## Usage

1. List all the public keys in OpenSSH's `authorized_key` format:

```sh
$ age-plugin-1p --print-recipients
op://Personal/SSH key/public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINKZfejb9htpSB5K9p0RuEowErkba2BMKaze93ZVkQIE
```

2. Encrypt file with SSH public key:

```sh
$ echo 'Hello, world!' | age -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINKZfejb9htpSB5K9p0RuEowErkba2BMKaze93ZVkQIE" -o secret.age
```

You can replace the recipient with `"$(op read "op://Personal/SSH key/public key")"` when encrypting files for yourself.

3. Decrypt file with:

`age` can automatically find the correct SSH key for decryption. Use `-j <name>`
to specifify the backend to be used.

```sh
$ age --decrypt -j 1p -o - secret.age # Use 1Password
$ age --decrypt -j bw -o - secret.age # Use Bitwarden
Hello, world!
```

## Supported SSH Key Types

Only Ed25519 and RSA keys are supported since these are the only types supported
by [1Password](https://developer.1password.com/docs/ssh/agent/#eligible-keys)
and
[age](https://github.com/FiloSottile/age/blob/482cf6fc9babd3ab06f6606762aac10447222201/agessh/agessh.go#L5-L7).

## Inspiration

This plugin is a spiritual successor of
[age-plugin-op](https://github.com/bromanko/age-plugin-op), where it shares a
little code, however the majority of code comes from
[age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm/) as it uses the new
[experimental plugin framework](https://github.com/FiloSottile/age/pull/580).
