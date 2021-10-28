#
# Cookbook Name:: jboss-eap
# Recipe:: eap7
#
# Copyright 2020, TRF2
#
# All rights reserved - Do Not Redistribute
#
# --------------------- Atencao ---------------------
module InfraEAP
  class CliResource < Chef::Resource
    resource_name :cli_resource
    property :name, String, default: 'resource'
    property :jboss_eap_dir, String, default: '/opt/jboss'
    property :profile_name, String, default: 'domain'
    property :resource_address, String, default: ''
    property :resource_type, String, default: 'system-property'
    property :port_offset, Integer, default: 0
    property :desired_state, Hash
    property :username, String, default: ''
    property :userpw, String, default: ''
    property :cert_path, String, default: ''
    property :eap_version, Float, default: 7.2
    property :jboss_owner, String, default: EAP::JBOSS_OWNER
    property :jboss_group, String, default: EAP::JBOSS_GROUP

    action :apply do
      if !new_resource.desired_state.empty?
        name = new_resource.name
        port_offset = new_resource.port_offset
        resource_address = new_resource.resource_address
        profile_name = new_resource.profile_name
        resource_type = new_resource.resource_type
        desired_state = new_resource.desired_state
        jboss_eap_dir = new_resource.jboss_eap_dir
        username = new_resource.username
        userpw = new_resource.userpw
        cert_path = new_resource.cert_path
        eap_version = new_resource.eap_version
        jboss_owner = new_resource.jboss_owner
        jboss_group = new_resource.jboss_group

        cli_script_path = "/tmp/#{profile_name}-#{name}-converge.cli"
        desired_state_path = "/tmp/#{profile_name}-#{name}-desired.json"

        file desired_state_path do
          content desired_state.to_json
        end

        #converge_args = (eap_version < 7) ? "#{node['ipaddress']}:#{9990 + port_offset}" : "https://#{node['fqdn']}:#{9993 + port_offset} --auth '#{username}:#{userpw}' --cert #{cert_path} --eap-version #{eap_version}"
        converge_args = "https://#{node['fqdn']}:#{9993 + port_offset} --auth '#{username}:#{userpw}' --cert #{cert_path} --eap-version #{eap_version}"
        execute "diff #{name} #{profile_name}" do
          command "python /util/jbosscli-converge/converge.py -c #{converge_args} --address '#{resource_address}' -t '#{resource_type}' -d #{desired_state_path} -o #{cli_script_path}"
        end

        jboss_cli_args = (eap_version < 7) ? "controller=#{node['ipaddress']}:#{9999 + port_offset} " : ""
        execute "apply diff #{name}" do
          command "sudo -u #{jboss_owner} #{jboss_eap_dir}/bin/jboss-cli.sh -c #{jboss_cli_args}--file=#{cli_script_path}"
        end
      end
    end
  end
end
