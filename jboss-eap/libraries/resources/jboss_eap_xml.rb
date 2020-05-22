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
    property :version, Float
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
      host_config_file = new_resource.host_config_file
      version = new_resource.version
      truststore_secret = f_truststore_secret()
      ldap_cert_path = f_ldap_cert_path()
      ldap_truststore_path = f_ldap_truststore_path()
      ldap_credstore_name = f_ldap_credstore_name()
      ldap_credstore_pw = f_ldap_credstore_pw()
      ldap_filter_base_dn = f_ldap_filter_base_dn()
      ldap_search_base_dn = f_ldap_search_base_dn()
      ldap_principal = f_ldap_principal()
      ldap_principal_pw = f_ldap_principal_pw()
      ldap_principal_acc = f_ldap_principal_acc()
      vault_ldap_cfg = f_vault_add_item(ldap_principal_acc, 'password', ldap_principal_pw)
      vault_init_xml = f_init_vault()
      ldap_server_url = f_ldap_server_url()
      https_truststore_path = f_https_truststore_path()

      f_init_ssl_cert_legacy64()
      
      host_config_path = "#{configuration_dir}/#{host_config_file}"
      template host_config_path do
        source "host-master-#{version}.xml.erb"
        owner 'jboss'
        group 'root'
        mode '0640'
        action :create
        variables(
          vault_init_xml: vault_init_xml,
          vault_ldap_cfg: vault_ldap_cfg,
          ldap_cert_path: ldap_cert_path,
          ldap_server_url: ldap_server_url,
          ldap_principal: ldap_principal,
          ldap_search_base_dn: ldap_search_base_dn,
          ldap_truststore_path: ldap_truststore_path,
          truststore_secret: truststore_secret,
          https_truststore_path: https_truststore_path
        )
        not_if "test -f #{host_config_path}"
      end

    end

    action :preconfig_domain do

      configuration_dir = new_resource.configuration_dir
      domain_config_file = new_resource.domain_config_file
      domain_version = new_resource.domain_version
      domain_name = new_resource.domain_name
      jboss_user_roles = f_jboss_user_roles()
      jboss_ldap_role_mappings = f_jboss_ldap_role_mappings()

      domain_config_path = "#{configuration_dir}/#{domain_config_file}"
      template domain_config_path do
        source "domain.xml-#{domain_version}.erb"
        owner 'jboss'
        group 'root'
        mode '0755'
        action :create
        variables(
          domain_name: domain_name,
          jboss_user_roles: jboss_user_roles, 
          jboss_ldap_role_mappings: jboss_ldap_role_mappings
        )
        not_if "test -f #{domain_config_path}"
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
      vault_init_xml = f_init_vault()
      slave_secret_b64 = new_resource.slave_secret_b64
      slave_secret = new_resource.slave_secret
      version = new_resource.version

      host_config_path = "#{configuration_dir}/#{host_config_file}"

      template host_config_path do
        source "host-slave-#{version}.xml.erb"
        owner 'jboss'
        group 'root'
        mode '0640'
        action :create
        variables(
          secret_b64: slave_secret_b64,
          master_ipaddress: master_ipaddress,
          master_port: 9999,
          vault_init_xml: vault_init_xml
        )
        not_if "test -f #{host_config_path}"
      end
    end

    action_class do
      include InfraEAP::Helper
      include InfraEAP::ConfHelper
    end
  end
end
