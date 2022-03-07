#! /bin/bash
set -euxo pipefail

cd /home/$(logname)

git clone https://github.com/rahularya50/gdp-routing-capsule.git rustgdp
systemctl start docker

echo "vm.nr_hugepages = 2048" >> /etc/sysctl.conf
sysctl -e -p

echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

newgrp docker
usermod -aG docker $(logname)

systemctl restart docker

echo 'docker run --rm   -id  --privileged     --network=host     --name sandbox     --cap-add=SYS_PTRACE     --security-opt seccomp=unconfined     -v /lib/modules:/lib/modules     -v /dev/hugepages:/dev/hugepages     -v /home/$(logname)/rustgdp:/gdp     -v/usr/local/cargo/registry:/usr/local/cargo/registry     getcapsule/sandbox:19.11.6-1.50 /bin/bash' > /usr/bin/startgdp
echo 'docker exec -it sandbox /bin/bash' > /usr/bin/rungdp
chmod +x /usr/bin/startgdp
chmod +x /usr/bin/rungdp
