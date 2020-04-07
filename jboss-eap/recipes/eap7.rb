#
# Cookbook Name:: jboss-eap
# Recipe:: eap7
#
# Copyright 2020, TRF2
#
# All rights reserved - Do Not Redistribute
# MERGED FROM DEFAULT.RB, HOST.RB and DC.RB
#
# --------------------- Atencao ---------------------

jboss_eap 'install eap' do
  action :install
end

jboss_eap 'add modules to eap' do
  action :add_module_from_repo
end

jboss_eap 'add zip modules to eap' do
  action :add_ext_pkgd_modules
end

jboss_eap "Setup Host Controller" do
  action :setup_controller
end



##### Apenas para quem usa josie...
mapping = node['server-group-mapping']

unless mapping.nil?
  template '/etc/server-group-mapping.properties' do
    source 'server-group-mapping.properties.erb'
    owner 'root'
    group 'root'
    variables(
      :mapping => mapping
    )
  end
end
