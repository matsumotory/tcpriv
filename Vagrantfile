Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-18.04"
  config.vm.provision "shell", :path => "misc/provision.sh", :privileged => false
  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 2
  end
  #config.vm.network "private_network", type: "dhcp", virtualbox__intnet: true
  config.vm.network "public_network"
end
