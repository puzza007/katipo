# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  config.vm.provision "shell", inline: <<-SHELL
    sudo echo 'deb http://packages.erlang-solutions.com/ubuntu trusty contrib' >> /etc/apt/sources.list
    wget http://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc
    sudo apt-key add erlang_solutions.asc
    sudo apt-get update
    sudo apt-get install -y git libwxgtk2.8-0 libwxbase2.8-0 libevent-dev libcurl4-openssl-dev libcurl4-openssl-dev esl-erlang language-pack-en
  SHELL
end
