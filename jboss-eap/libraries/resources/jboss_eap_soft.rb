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
  class JBossEAPSoft < Chef::Resource
 
    resource_name :jboss_eap_soft

    default_action :install

    property :name, String

    #path do link simbólico que será criado para o diretório real da instalação.
    property :jboss_eap_dir, String

    # numero da major version
    property :major_version, Integer

    # numero da versao
    property :version, Float

    # nome do grupo a ser instalado: yum groupinstall <yum_group_name>
    property :yum_group_name, String

    #informações para instalação de software adicional
    property :util_soft_repo_cfg, Hash

    #intallation type
    property :is_rpm, [TrueClass, FalseClass]

    #EAP zip packge url
    property :eap_zip_url, String
    

    action :install do
      name               = new_resource.name
      jboss_eap_dir      = new_resource.jboss_eap_dir
      major_version      = new_resource.major_version
      version = new_resource.version
      yum_group_name     = new_resource.yum_group_name
      util_soft_repo_cfg = new_resource.util_soft_repo_cfg
      is_rpm = new_resource.is_rpm
      eap_zip_url = new_resource.eap_zip_url
      jboss_user = f_jboss_user()
      jboss_group = f_jboss_group()
      jboss_install_dir = f_install_home_dir(major_version, version)
      jboss_srv_conf_path = f_install_service_conf_path(major_version)
      jboss_srv_conf_link_path = f_install_service_conf_ln_path(major_version)
      domain_dir = f_domain_dir()
      vault_dir = f_vault_dir()
      
      if f_force_reinstall()
        ruby_block 'call_me_back_action:uninstall' do
          block do
            action_uninstall
          end
          action :run
        end
      end
      
      if is_rpm
        execute "Installing Group #{yum_group_name}" do
          command "yum -y groupinstall #{yum_group_name}"
          action :run
        end

        link jboss_eap_dir do
          to jboss_install_dir
          owner 'root'
          group 'root'
          not_if { jboss_eap_dir.eql?(jboss_install_dir) }
        end
      else
        if version < 6.4
          package %w(java-1.8.0-openjdk java-1.8.0-openjdk-headless) do
            action :remove
          end

          package %w(java-1.6.0-openjdk java-1.7.0-openjdk)
        else
          package 'java-1.8.0-openjdk'
        end

        eap_zip_file_name =  eap_zip_url.split('/')[-1]
        eap_zip_local_path = "/tmp/#{eap_zip_file_name}"

        if !jboss_user.eql?(jboss_group)
          group jboss_group do
            action :create
          end
        end
          
        user jboss_user do
          comment 'JBoss EAP user'
          uid 185
          if !jboss_user.eql?(jboss_group)
          gid jboss_group
          end
          home jboss_install_dir
          system true
          shell '/sbin/nologin'
          manage_home false
          password (0...50).map { ('a'..'z').to_a[rand(26)] }.join
          action :create
        end

        remote_file eap_zip_local_path do
          source eap_zip_url
          owner 'root'
          group 'root'
          mode '0644'
          action :create
          not_if "test -f #{eap_zip_local_path}"
        end

        execute "unzip -n #{eap_zip_local_path} -d #{EAP::SUB_HOME}"

        link jboss_install_dir do
          to lazy{ f_dirname_on_zip(eap_zip_local_path) }
        end

        link jboss_eap_dir do
          to jboss_install_dir
          owner 'root'
          group 'root'
          not_if { jboss_eap_dir.eql?(jboss_install_dir) }
        end

        directory f_log_dir() do
          owner 'jboss'
          group 'root'
          mode '0750'
          action :create
          not_if { ::File.exist?(f_log_dir()) }
        end
        
        directory f_data_dir() do
          owner 'jboss'
          group 'root'
          mode '0750'
          action :create
          not_if { ::File.exist?(f_data_dir()) }
        end

        execute 'Acerta permissões do domain' do
          command "chown -R jboss #{f_domain_dir()}"
          action :run
        end
        
        #execute "chown -R root.jboss #{jboss_install_dir}"
      end

      directory vault_dir do
        owner 'jboss'
        group 'root'
        mode '0750'
        action :create
      end

      if !jboss_srv_conf_link_path.empty?
        v_idx_last_b = jboss_srv_conf_link_path.rindex('/')
        v_link_parent_dir = jboss_srv_conf_link_path[0 .. v_idx_last_b - 1]
        v_idx_l_b_v_dir = v_link_parent_dir.rindex('/')

        if v_idx_last_b !=0 && v_idx_l_b_v_dir != 0
          directory v_link_parent_dir do
            owner 'root'
            group 'root'
            mode '0755'
            action :create
          end

          link jboss_srv_conf_link_path do
            to f_install_service_conf_path(major_version)
          end
        end
      end

      directory f_sys_log_base_dir() do
        owner 'root'
        group 'root'
        mode '0750'
        action :create
        recursive true
      end

      link "#{f_sys_log_base_dir()}/domain" do
        to f_log_dir()
      end

      auxsoft_base_dir = f_util_soft_base_dir(util_soft_repo_cfg)
      auxsoft_repo_cfg = f_util_soft_cfg(util_soft_repo_cfg)

      if auxsoft_repo_cfg.any?

        auxsoft_repo_cfg.each_pair do |auxsoft_name, auxsoft_install_cfg|
          
          req_packages = f_util_soft_req_packages(auxsoft_install_cfg)
          
          if req_packages.any?
            package req_packages
          end

          auxsoft_path = "#{auxsoft_base_dir}/#{auxsoft_name}"
          auxsoft_req_add_path = f_util_soft_add_path(auxsoft_install_cfg)
          auxsoft_req_path = auxsoft_req_add_path + [auxsoft_path]

          auxsoft_req_path.each do |req_path_item|
            directory req_path_item do
              owner 'root'
              group 'root'
              mode '0750'
              action :create
              recursive true
            end
          end

          auxsoft_gitrepo = f_util_soft_git_repo(auxsoft_install_cfg)
          auxsoft_git_enble_submdle = f_util_soft_git_ena_submodule(auxsoft_install_cfg)

          git auxsoft_path do
            repository auxsoft_gitrepo
            enable_submodules auxsoft_git_enble_submdle
            action :sync
          end

          auxsoft_command = f_util_soft_command_file(auxsoft_install_cfg)

          auxsoft_command.each do |command_name|
            execute "chmod a+x #{auxsoft_path}/#{command_name}"
          end
        end
      end
    end
   
    action :uninstall do
      util_soft_repo_cfg = new_resource.util_soft_repo_cfg
      yum_group_name     = new_resource.yum_group_name
      is_rpm = new_resource.is_rpm
      version = new_resource.version
      major_version = new_resource.major_version
      jboss_install_dir = f_install_home_dir(major_version, version)

      template '/tmp/uninstal.sh' do
        source 'uninstall.sh.erb'
        owner 'root'
        group 'root'
        mode '0755'
        action :create
        variables(
          jboss_instances: '',
          yum_group_name: yum_group_name,
          jboss_install_dir: jboss_install_dir,
          is_rpm: is_rpm,
          user: f_jboss_user(),
          group: f_jboss_group()
        )
      end

      execute 'Uninstall JBoss EAP' do
        command '/tmp/uninstal.sh'
        action :run
      end

      log 'Removing additional software tools'
      #não removendo packages e basedir para não quebrar demais softwares instalados.
      auxsoft_base_dir = f_util_soft_base_dir(util_soft_repo_cfg)
      auxsoft_repo_cfg = f_util_soft_cfg(util_soft_repo_cfg)

      if auxsoft_repo_cfg.any?

        auxsoft_repo_cfg.each_pair do |auxsoft_name, auxsoft_install_cfg|
          
          auxsoft_path = "#{auxsoft_base_dir}/#{auxsoft_name}"
          auxsoft_req_add_path = f_util_soft_add_path(auxsoft_install_cfg)
          auxsoft_req_path = auxsoft_req_add_path + [auxsoft_path]

          auxsoft_req_path.each do |req_path_item|
            directory req_path_item do
              action :delete
              recursive true
            end
          end
        end
      end
      
    end

    action_class do
      include InfraEAP::Helper
    end
  end
end