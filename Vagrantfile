# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# One box per family, named after the distribution row it proves. Each box runs
# ci/selfcheck.sh with --expect-driver set to the driver its image should load, so a
# box that silently falls back to the wrong driver fails instead of passing quietly.
#
#   vagrant up ubuntu-2404 && vagrant provision ubuntu-2404
#   vagrant status                     # what is running and what family it claims
#   vagrant ssh rocky-9 -c 'sudo bash /vagrant/tests/live_check.sh --family rhel ...'
#
# The provider is whatever Vagrant finds first: libvirt or VirtualBox on a workstation,
# hyperv on Windows. These images need a real init system, so a container is not a
# substitute; that difference is the whole reason this file exists next to the GitHub
# matrix rather than instead of it.

Vagrant.configure("2") do |config|
  # Synced folder rather than a provisioner that copies: the code under test is the
  # working tree, so a change on the host is visible in the box on the next run.
  config.vm.synced_folder ".", "/vagrant"

  # Each row states the family its image is expected to resolve to. Keep this list in
  # step with ci/README.md, and add the matching row to the Actions matrix.
  boxes = [
    { name: "debian-12",     image: "debian/bookworm64",        driver: "debian" },
    { name: "ubuntu-2404",   image: "generic/ubuntu2404",       driver: "debian" },
    { name: "ubuntu-2204",   image: "generic/ubuntu2204",       driver: "debian" },
    { name: "rocky-9",       image: "rockylinux/9",             driver: "rhel" },
    { name: "alma-8",        image: "almalinux/8",              driver: "rhel" },
    { name: "fedora-42",     image: "generic/fedora42",         driver: "rhel" },
    { name: "leap-156",      image: "opensuse/Leap-15.6.x86_64", driver: "suse" },
    # EL7 is the bash 4.2 and authconfig case. Its public boxes are archived and its
    # mirrors are retired, so it is listed but never brought up by default: enable it
    # with VAGRANT_EL7_BOX set to a box that installs git, or run an EL7 host by hand.
    { name: "centos-7",      image: ENV["VAGRANT_EL7_BOX"] || "generic/rhel7", driver: "rhel", optional: true },
  ]

  boxes.each do |box|
    config.vm.define box[:name], box[:optional] ? false : true do |node|
      node.vm.box = box[:image]
      node.vm.hostname = "lsb-#{box[:name]}"
      node.vm.provider("libvirt") { |p| p.memory = "1024"; p.cpus = 1 }
      node.vm.provider("virtualbox") { |p| p.memory = "1024"; p.cpus = 1 }
      node.vm.provider("hyperv") { |p| p.memory = 1024 }

      # Only what the check itself needs. The baseline's own package choices stay in
      # the stages, so a box never silently installs something a driver does not name.
      node.vm.provision "shell", inline: <<-SCRIPT
        set -eux
        . /etc/os-release
        case " ${ID:-} ${ID_LIKE:-} " in
          *debian*|*ubuntu*)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq --no-install-recommends sudo curl ;;
          *fedora*|*rhel*|*centos*|*rocky*|*alma*)
            if command -v dnf >/dev/null 2>&1; then
              dnf install -y -q curl
            else
              yum install -y -q curl
            fi ;;
          *suse*|*leap*|*sles*)
            zypper --non-interactive install curl || \
              zypper --non-interactive install curl-devel ;;
        esac
        bash /vagrant/ci/selfcheck.sh --expect-driver #{box[:driver]}
      SCRIPT
    end
  end
end
