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
  class JBossEAP < Chef::Resource
    resource_name :jboss_eap

    default_action :install

    allowed_actions :install, :add_ext_pkgd_modules, :add_module_from_repo, :uninstall, :setup_controller 

    property :name, String

    #se, usando a forma de zip, será sobrescrito o arquivo já existente no servidor ou não.
    property :ext_module_force_update, [TrueClass, FalseClass], default: false

    #property :force_restart, [TrueClass, FalseClass], default: false

    property :force_setup, [TrueClass, FalseClass], default: true

    action :install do
      name               = new_resource.name
      jboss_eap_dir      = f_eap_dir()
      major_version      = f_my_mj_version()     
      util_soft_repo_cfg = f_util_soft_install_cfg()
      yum_group_name     = f_yum_groupname()
      is_rpm = f_is_rpm_install()
      eap_zip_url = f_eap_zip_url()
      version = f_my_version()

      jboss_eap_soft name do
        action :install
        jboss_eap_dir jboss_eap_dir
        major_version major_version
        yum_group_name  yum_group_name
        util_soft_repo_cfg util_soft_repo_cfg
        is_rpm is_rpm
        eap_zip_url eap_zip_url
        version version
      end

    end

    action :add_ext_pkgd_modules do
      jboss_eap_dir             = f_eap_dir()
      jboss_modules_dir         = f_modules_dir()
      ext_module_zip_url = f_ext_module_zip_url()
      ext_module_force_update   = new_resource.ext_module_force_update
      ext_module_cfg            = f_modules_cfg()

      if !ext_module_zip_url.nil? && !ext_module_zip_url.empty?
        ext_module_local_filename = ext_module_zip_url.split('/')[-1]
        ext_module_zip_path       = "/tmp/#{ext_module_local_filename}"
        jboss_eap_module 'download and install packaged modules' do
          action :add_pkg
          jboss_eap_dir jboss_eap_dir
          ext_module_cfg  ext_module_cfg
          ext_module_base_url ext_module_zip_url
          csv_content ''
          ext_module_force_update ext_module_force_update
          jboss_modules_dir jboss_modules_dir
        end
      end
     
    end

    action :add_module_from_repo do
      pulp_manifest_url               = f_ext_module_pulp_manifest()
      ext_module_cfg                  = f_modules_cfg()
      jboss_eap_dir                   = f_eap_dir()
      jboss_modules_dir         = f_modules_dir()
      ext_module_force_update         = new_resource.ext_module_force_update
      local_manifest_path             = '/tmp/REPO_PULP_MANIFEST'
      if !pulp_manifest_url.nil? && !pulp_manifest_url.empty?
        ext_module_base_url             = f_base_url(pulp_manifest_url)
        remote_file local_manifest_path do
          source pulp_manifest_url
          owner 'root'
          group 'root'
          mode '0640'
          action :create
        end

        jboss_eap_module 'download and install modules' do
          action :add
          jboss_eap_dir jboss_eap_dir
          jboss_modules_dir jboss_modules_dir
          ext_module_cfg  ext_module_cfg
          ext_module_base_url ext_module_base_url
          csv_content lazy { ::IO.read(local_manifest_path) }
          ext_module_force_update ext_module_force_update
        end
      end
    end

    action :uninstall do
      name = new_resource.name
      util_soft_repo_cfg = new_resource.util_soft_repo_cfg
      yum_group_name = f_yum_groupname()
      is_rpm = f_is_rpm_install()
      eap_zip_url = f_eap_zip_url()
      version = f_my_version()
      major_version = f_my_mj_version()   

      jboss_eap_soft name do
        util_soft_repo_cfg util_soft_repo_cfg
        yum_group_name yum_group_name
        version version
        major_version major_version
        is_rpm is_rpm
        eap_zip_url eap_zip_url
        action :uninstall
      end
    end

    action :setup_controller do
      name = new_resource.name
      force_setup = new_resource.force_setup
      jboss_eap_dir   = f_eap_dir()
      domain_cfg = f_domain_cfg()
      master_ipaddress = f_master_ipaddress()
      master_fqdn = f_master_fqdn()
      slave_names = f_non_legacy_slavenames()
      legacy_slave_names = f_legacy_slavenames()
      domain_name = f_domain_name()
      is_master = am_i_master()
      major_version = f_my_mj_version()
      my_version = f_my_version()
      domain_version = f_domain_version()
      service_name = f_my_service_name()
      configuration_dir = f_config_dir()
      log_dir = f_log_dir()
      truststore_dir = f_truststore_dir()
      credstore_dir = f_credstore_dir()
      master_cert_path = "#{f_sys_cert_dir()}/#{master_fqdn}.crt"
      started_code = f_started_code()
      host_config_file = f_config_file_name(false, is_master, domain_name)
      domain_config_file = f_config_file_name(true, is_master, domain_name)
      profiles_cfg = f_my_profiles()
      

      domain_system_properties =  f_system_properties(domain_cfg)

      [credstore_dir, truststore_dir].each do |one_dir|
        directory one_dir do
          owner 'jboss'
          group 'jboss'
          mode '0750'
          action :create
        end
      end

      jboss_eap_conf 'Setup controller' do
        jboss_eap_dir jboss_eap_dir
        domain_name domain_name
        service_name service_name
        master_ipaddress master_ipaddress
        major_version major_version
        version my_version
        domain_version domain_version
        master_fqdn master_fqdn
        profiles_cfg  profiles_cfg
        truststore_dir truststore_dir
        credstore_dir credstore_dir
        master_cert_path master_cert_path
        configuration_dir configuration_dir
        log_dir log_dir
        slave_names slave_names
        legacy_slave_names legacy_slave_names
        is_master is_master
        started_code started_code
        domain_config_file domain_config_file
        host_config_file host_config_file
        force_setup force_setup
        domain_system_properties domain_system_properties
        action :setup
      end

    end

    action_class do
        include InfraEAP::Helper
    end
  end
end