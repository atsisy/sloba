import sys
import subprocess

args = sys.argv

qemu = 'qemu-system-x86_64'
kvm = 'qemu-kvm'
default_option = ' -kernel ./linux/arch/x86_64/boot/bzImage -initrd ./rootfs.img -append "root=/dev/ram console=ttyS0,115200n8 panic=3 rdinit=/bin/sh" -no-reboot -boot c -nographic'
debug_option = ' -gdb tcp::10000 -S'

if args[1] == 'qemu':
    subprocess.call(qemu + default_option, shell=True)
elif args[1] == 'kvm':
    subprocess.call(kvm + default_option, shell=True)
elif args[1] == 'qemu-debug':
    subprocess.call(qemu + default_option + debug_option, shell=True)
elif args[1] == 'kvm-debug':
    subprocess.call(kvm + default_option + debug_option, shell=True)
else:
    print("invalid command line option.");
