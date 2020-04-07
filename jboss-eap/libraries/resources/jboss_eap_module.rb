#
# Cookbook Name:: jboss-eap
# Recipe:: eap7
#
# Copyright 2020, TRF2
#
# All rights reserved - Do Not Redistribute
#
# --------------------- Atencao ---------------------
require 'csv'
module InfraEAP
  class JBossEAPModule < Chef::Resource
    resource_name :jboss_eap_module

    property :name, String
    property :jboss_eap_dir, String
    property :jboss_modules_dir, String
    property :csv_content, String
    property :ext_module_cfg, Hash
    property :ext_module_base_url, String
    property :ext_module_force_update, [TrueClass, FalseClass]

    action :add do
      name                = new_resource.name
      jboss_eap_dir       = new_resource.jboss_eap_dir
      jboss_modules_dir   = new_resource.jboss_modules_dir
      csv_content         = new_resource.csv_content
      ext_module_cfg      = new_resource.ext_module_cfg
      ext_module_base_url = new_resource.ext_module_base_url
      ext_module_force_update = ext_module_force_update
      
      csv_keys            = ['package', 'checksum','size']

      pulp_modules_info = CSV.parse(csv_content).map {|a| Hash[ csv_keys.zip(a) ] }
      
      log "Base URL: #{ext_module_base_url}"

      ext_module_cfg.each_pair do |_idx, module_item|
        module_name = module_item.fetch('driver-module-name')
        module_filename = module_item.fetch('file')
        module_group = module_item.fetch('group','')
        module_dir = "#{jboss_modules_dir}/#{module_name.tr('.', '/')}/main"

        package_rmt_info =  pulp_modules_info.select {|pulp_module| pulp_module["package"].include? "#{module_group}/#{module_filename}" }

        log package_rmt_info.inspect

        if package_rmt_info.one?
          package_rmt_info = package_rmt_info.first
          package_rmt_path = package_rmt_info.fetch('package')
          package_local_path = "#{module_dir}/#{module_filename}"

          directory module_dir do
            recursive true
            owner 'root'
            group 'root'
            mode  '0755'
          end      

          remote_file package_local_path do
            source (ext_module_base_url + package_rmt_path)
            owner 'root'
            group 'root'
            mode '0644'
            checksum package_rmt_info.fetch('checksum')
            action :create
          end

          template "#{module_dir}/module.xml" do
            source 'module.xml.erb'
            owner 'root'
            group 'root'
            mode  '0644'
            variables(
              :module_name => module_name,
              :driver_file => module_filename
            )
          end
          
        else
          log "MODULE not found: #{ext_module_base_url + package_rmt_info.inspect}" do
            level :fatal
          end
        end
      end
    end

    action :add_pkg do
      jboss_eap_dir             = new_resource.jboss_eap_dir
      jboss_modules_dir   = new_resource.jboss_modules_dir
      ext_module_zip_url        = new_resource.ext_module_base_url
      ext_module_local_filename = ext_module_zip_url.split('/')[-1]
      ext_module_zip_path       = "/tmp/#{ext_module_local_filename}"
      ext_module_force_update   = new_resource.ext_module_force_update

      remote_file ext_module_zip_path do
        source ext_module_zip_url
        ignore_failure true
      end

      execute "if [[ -f #{ext_module_zip_path} ]]; then unzip #{(ext_module_force_update) ? '-o' : '-n' } #{ext_module_zip_path} -d #{jboss_modules_dir}; else echo sem package na url; fi" do
        action :run
        live_stream true
      end
    end
  end
end