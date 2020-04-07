#
# Cookbook Name:: jboss-eap
# Recipe:: eap7
#
# Copyright 2020, TRF2
#
# All rights reserved - Do Not Redistribute
#
# --------------------- Atencao ---------------------
# require 'rexml/document'
module InfraEAP
  class JBossEAPXML < Chef::Resource
#    include REXML
    resource_name :jboss_eap_xml

    default_action :config_slave

    property :name, String
    property :jboss_eap_dir, String
    property :major_version, Integer
    property :domain_version, Float
    property :domain_name, String
    property :master_ipaddress, String
    property :master_fqdn, String
    property :is_master, [TrueClass, FalseClass]
    property :master_cert_path, String
    property :update_master_cert, [TrueClass, FalseClass]
    property :configuration_dir, String
    property :log_dir, String
    property :truststore_dir, String
    property :host_config_file, String
    property :domain_config_file, String
    property :slave_secret, String
    property :slave_secret_b64, String
    property :truststore_secret, String
    property :has_pvt_jg_nw, [TrueClass, FalseClass]
    property :pvt_if_ipaddr, String
    property :host_config_content, String
    property :profile_content, String
    property :domain_content, String
    property :profile_name, String

    action :add_profile do
      configuration_dir = new_resource.configuration_dir
      domain_config_file = new_resource.domain_config_file
      profile_content = new_resource.profile_content
      domain_content = new_resource.domain_content
      profile_name = new_resource.profile_name
      
      if  !domain_content.include? "<profile name=\"#{profile_name}\""
        new_domain_content = domain_content.split('<profiles>').join("<profiles>\n#{profile_content}")

        file "#{configuration_dir}/#{domain_config_file}" do
          content new_domain_content
          owner 'jboss'
          group 'root'
          mode '0640'
          action :create
        end
      end
    end
    
    action :config_master do
      configuration_dir = new_resource.configuration_dir
      host_config_file = new_resource.configuration_dir
      major_version = new_resource.major_version
      
      host_config_path = "#{configuration_dir}/#{host_config_file}"
      template host_config_path do
        source "host-master-#{major_version}.xml.erb"
        owner 'jboss'
        group 'root'
        mode '0755'
        action :create
        not_if { File.exist(host_config_path) }
      end

    end

    action :preconfig_domain do

      configuration_dir = new_resource.configuration_dir
      domain_config_file = new_resource.domain_config_file
      domain_version = new_resource.domain_version

      domain_config_path = "#{configuration_dir}/#{domain_config_file}"
      template domain_config_path do
        source "domain-#{domain_version}.xml.erb"
        owner 'jboss'
        group 'root'
        mode '0755'
        action :create
        variables(
          domain_name: domain_name
        )
        not_if { File.exist(domain_config_path) }        
      end

    end

    action :config_slave do
      jboss_eap_dir = new_resource.jboss_eap_dir
      master_ipaddress = new_resource.master_ipaddress
      master_fqdn = new_resource.master_fqdn
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      configuration_dir = new_resource.configuration_dir
      master_cert_path = new_resource.master_cert_path
      
      slave_secret_b64 = new_resource.slave_secret_b64
      slave_secret = new_resource.slave_secret
      major_version = new_resource.major_version

      host_config_path = "#{configuration_dir}/#{host_config_file}"

      template host_config_path do
        source "host-slave-#{major_version}.xml.erb"
        owner 'jboss'
        group 'root'
        mode '0640'
        action :create
        variables(
          secret_b64: slave_secret_b64,
          master_ipaddress: master_ipaddress,
          master_port: 9999,
        )
        not_if "test -f #{host_config_path}"
      end
    end

    action_class do
      include InfraEAP::Helper
    end
  end
end
