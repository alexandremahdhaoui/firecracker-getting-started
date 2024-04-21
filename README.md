# firecracker-getting-started

## Prerequisites

### Clone this repository

```shell
git clone https://github.com/alexandremahdhaoui/firecracker-getting-started
cd firecracker-getting-started
```

### Install firecracker

Please refer to the official documentation:
https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md#getting-a-firecracker-binary


## Part I. Getting started

This guide is merely a revamp of the firecracker's 
[Getting Started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md) document.

### Building a kernel

[Source](https://github.com/firecracker-microvm/firecracker/blob/main/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config)

```shell
KERNEL_VERSION=6.1.87

# --- 1. download kernel source code
URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION//.*}.x/linux-${KERNEL_VERSION}.tar.xz"
curl -sfL "${URL}" | tar -xJ

# --- 2. download recommended config
curl -sfLo "./linux-${KERNEL_VERSION}/.config" https://github.com/firecracker-microvm/firecracker/blob/main/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config

# --- 3. set up a kernel builder container
cat <<'EOF' | podman build -t kernel-builder -f -
FROM debian:bookworm
RUN apt-get -y update 
RUN apt-get -y install curl make gcc flex bison bc libncurses-dev \
    libelf-dev libssl-dev xz-utils
EOF

# --- 4. build the kernel
cat <<EOF | podman run --rm -i -v `pwd`:/workdir kernel-builder
cd "/workdir/linux-${KERNEL_VERSION}"
make vmlinux -j`nproc`
EOF
```

### Build a rootfs

```shell
# --- 1. create a small fs
dd if=/dev/zero of=rootfs.ext4 bs=1M count=150
mkfs.ext4 rootfs.ext4
mkdir rootfs
sudo mount rootfs.ext4 rootfs

# --- 2. prepare the rootfs
cat <<'EOF' | sudo podman run -i --rm -v `pwd`:/workdir alpine
# add a pid 1 + some utils and openssh
apk add --no-cache openrc util-linux openssh

# setup ssh
ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -q -N ""
# create an ssh to connect to the vm.
ssh-keygen -t ed25519 -f /workdir/id_ed25519 -q -N ""
cat /workdir/id_ed25519.pub > /root/.ssh/authorized_keys
rm /workdir/id_ed25519.pub

# setup ttyS0
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
rc-update add agetty.ttyS0 default

# ensures special file systems are mounted on boot
rc-update add devfs boot
rc-update add procfs boot
rc-update add sysfs boot

echo /bin /etc /lib /root /sbin /usr | xargs -n 1 tar c | tar x -C /workdir/rootfs
mkdir -p /workdir/rootfs/{dev,proc,run,sys,var}
EOF

# --- 3. unmount rootfs
sudo umount rootfs
rm -rf rootfs
```

### Start a firecracker vm

#### Run the firecracker process

```shell
{
  API_SOCKET="./firecracker.socket"
  sudo rm -f $API_SOCKET
  sudo firecracker --api-sock "${API_SOCKET}"
}
```

#### Prepare the vm

```shell
KERNEL_VERSION=6.1.87
# --- 0. Config
TAP_DEV="tap0"
TAP_IP="172.16.0.1"
FC_MAC="06:00:AC:10:00:02"
MASK_SHORT="/30"
HOST_IFACE="eth0"

API_SOCKET="./firecracker.socket"
LOGFILE="./firecracker.log"

KERNEL="./linux-${KERNEL_VERSION}/vmlinux"
KERNEL_BOOT_ARGS="console=ttyS0 reboot=k panic=1 pci=off"
ROOTFS="./rootfs.ext4"


# --- 1. Host network setup 
# Setup network interface
sudo ip link del "$TAP_DEV" 2> /dev/null || true
sudo ip tuntap add dev "$TAP_DEV" mode tap
sudo ip addr add "${TAP_IP}${MASK_SHORT}" dev "$TAP_DEV"
sudo ip link set dev "$TAP_DEV" up
# Enable ip forwarding
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
# Set up microVM internet access
sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE || true
sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
    || true
sudo iptables -D FORWARD -i tap0 -o "$HOST_IFACE" -j ACCEPT || true
sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE
sudo iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -I FORWARD 1 -i tap0 -o "$HOST_IFACE" -j ACCEPT

# --- 2. Add logging
touch $LOGFILE
sudo curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"log_path\": \"${LOGFILE}\",
        \"level\": \"Debug\",
        \"show_level\": true,
        \"show_log_origin\": true
    }" \
    "http://localhost/logger"

# --- 3. Set kernel
sudo curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"kernel_image_path\": \"${KERNEL}\",
        \"boot_args\": \"${KERNEL_BOOT_ARGS}\"
    }" \
    "http://localhost/boot-source"

# --- 4. Set rootfs
sudo curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"drive_id\": \"rootfs\",
        \"path_on_host\": \"${ROOTFS}\",
        \"is_root_device\": true,
        \"is_read_only\": false
    }" \
    "http://localhost/drives/rootfs"

# --- 5. Set guest network if
sudo curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"iface_id\": \"net1\",
        \"guest_mac\": \"$FC_MAC\",
        \"host_dev_name\": \"$TAP_DEV\"
    }" \
    "http://localhost/network-interfaces/net1"
```

#### Start the vm

```shell
# --- 1. Start the vm
sudo curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"action_type\": \"InstanceStart\"
    }" \
    "http://localhost/actions"

# --- 2. Setup internet access in the guest
ssh -i id_ed25519 root@172.16.0.2 "ip route add default via 172.16.0.1 dev eth0"

# --- 3. Setup dns resolution
ssh -i id_ed25519 root@172.16.0.2 "echo 'nameserver 8.8.8.8 > /etc/resolv.conf"

# --- 4. Finaly SSH into guest
ssh -i id_ed25519 root@172.16.0.2
```

### Initial vm configuration without API requests

OpenAPI Specification: https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml

```shell

```


```shell

```


```shell

```


```shell

```

