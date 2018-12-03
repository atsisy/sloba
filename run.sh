#!/bin/bash

for OPT in "$@"
do
    case $OPT in
        'qemu' )
            QEMU_FLAG=1
            ;;
        'kvm' )
            KVM_FLAG=1
            ;;
        '-d' )
            DEBUG_FLAG=1
            ;;
    esac
    shift
done

cmd=''
qemu='qemu-system-x86_64'
kvm='qemu-kvm'
default_option=' -kernel ./linux/arch/x86_64/boot/bzImage -initrd ./rootfs.img -append "root=/dev/ram console=ttyS0,115200n8 panic=3 rdinit=/bin/sh" -no-reboot -boot c -nographic'
debug_option=' -gdb tcp::10000 -S'


if [ "$QEMU_FLAG" ];
then
    cmd=$cmd$qemu
fi

if [ "$KVM_FLAG" ];
then
    cmd=$cmd$kvm
fi

if [ "$DEBUG_FLAG" ];
then
    cmd=$cmd$debug_option
fi

cmd=$cmd$default_option

eval ${cmd}
