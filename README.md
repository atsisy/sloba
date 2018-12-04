# sloba
Simple and fast slab allocator using slob interface

SLOBAはSLOBのソースコードを見て0から書き直したシンプルで高速なSlab allocatorです。

# How to develop

開発を簡単に行うためにいくつかのシェルスクリプトを用意しました。

I prepared several shell scripts for easier development.

## Initialize

```sh
$ ./init.sh
```

このスクリプトはGitHubからLinuxカーネルのGitリポジトリをダウンロードします。

This script downloads linux kernel git repository.

## Build

```sh
$ ./build.sh
```

このスクリプトはsrc/slob.c, src/slab.hをlinux/mm下にコピーしカーネルのビルドを行います。

This script copies src/slob.c and src/slab.h under linux/mm and builds the kernel.

```sh
$ ./build.sh update-config

```

"update-config"をオプションとして追加すると、src/.configをカーネルソースツリーのトップにコピーします。

If you add "update-config" as an option for build.sh, this script copies src/.config to the top of the kernel source tree.

## Run

```sh
$ ./run.sh [VM]
```

このスクリプトはビルドされたカーネルをqemuまたはqemu-kvm上で動作させます。

This script will let bzImage runs on qemu or qemu-kvm.

VMのオプションは以下の通りです。

You can choose VM from followings.

| Options | Description |
|:-----------|:------------|
| qemu | qemu-system-x86_x64 |
| kvm | qemu-kvm |
| qemu-debug | qemu-system-x86_x64 with gdb debugging |
| kvm-debug | qemu-kvm with gdb debugging |

# LICENSE

GPL v2
