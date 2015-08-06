# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y git libwxgtk2.8-0 libwxbase2.8-0 libevent-dev libcurl4-openssl-dev libcurl4-openssl-dev
    wget -o /dev/null http://packages.erlang-solutions.com/site/esl/esl-erlang/FLAVOUR_1_esl/esl-erlang_18.0-1~ubuntu~trusty_amd64.deb
    sudo dpkg -i esl-erlang_18.0-1~ubuntu~trusty_amd64.deb
  SHELL
end
