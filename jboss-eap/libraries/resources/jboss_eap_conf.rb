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
  class JBossEAPConf < Chef::Resource

    resource_name :jboss_eap_conf

    property :name, String
    property :jboss_eap_dir, String
    property :major_version, Integer
    property :version, Float
    property :domain_version, Float
    property :domain_name, String
    property :slave_names, Array
    property :legacy_slave_names, Array
    property :cluster_address, Array
    property :master_ipaddress, String
    property :master_fqdn, String
    property :is_master, [TrueClass, FalseClass]
    property :configuration_dir, String
    property :log_dir, String
    property :truststore_dir, String
    property :credstore_dir, String
    property :started_code, String
    property :profile_cfg, Hash
    property :host_config_file, String
    property :domain_config_file, String
    property :service_name, String
    property :master_cert_path, String
    property :force_setup, [TrueClass, FalseClass]
    property :profiles_cfg, Hash
    property :domain_system_properties, Hash

    action :take_snapshot do
      jboss_eap_dir = new_resource.jboss_eap_dir
      domain_config_file = new_resource.domain_config_file
      host_config_file = new_resource.host_config_file
      major_version = new_resource.major_version
      service_name = new_resource.service_name

      first_config_run = ::File.exist?("#{jboss_eap_dir}/first_config_run")
      
      if (first_config_run && major_version > 6) || f_is_service_active(service_name)
        snap_args = major_version < 7 ? '': "name=before_chef_run_#{::Time.now.strftime('%Y%m%d_%H%M%S')}_"
        cli_command = "#{major_version < 7 ? '': 'try, '}/host=#{node['hostname']}:take-snapshot(#{snap_args}), "
        cli_command = "#{cli_command}if (result != \"undefined\") of /:query(select=[process-type],where=[process-type,\"Domain Controller\"]), "
        cli_command = "#{cli_command}/:take-snapshot(#{snap_args}), end-if"
        cli_command = "#{cli_command}#{major_version < 7 ? '': ', catch, echo IhTvErroNaFirstRun, end-try'}"
        exec_cli_resource cli_command do
          live_stream true
          run_offline major_version > 6
          echo_command major_version > 6
          major_version major_version
          host_config_file host_config_file
          domain_config_file domain_config_file
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
        end
      end
    end

    action :setup_master do
      name                = new_resource.name
      jboss_eap_dir       = new_resource.jboss_eap_dir
      configuration_dir = new_resource.configuration_dir
      truststore_dir = new_resource.truststore_dir
      domain_name = new_resource.domain_name
      domain_version = new_resource.domain_version
      is_master = new_resource.is_master
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      credstore_dir = new_resource.credstore_dir
      profiles_cfg = new_resource.profiles_cfg
      major_version = new_resource.major_version
      version = new_resource.version
      truststore_secret = f_truststore_secret()
      is_remote_log = f_is_remote_log()
      logserver_addr = f_logserver_addr()
      logserver_port = f_logserver_port()
      logserver_protocol =  f_logserver_protocol()
      console_ports = f_default_master_console_port()
      cluster_port = f_default_cluster_port()
      master_ssl_keystore = f_master_ssl_keystore()
      https_truststore_path = f_https_truststore_path()
      lowest_version_on_domain = f_lowest_slave_version()
      service_name = new_resource.service_name
      started_code = new_resource.started_code
      log_dir = new_resource.log_dir
      
      console_ports.each do |one_port|
        execute "OpenConsole Port #{one_port}" do
          command "firewall-cmd --add-port=#{one_port}/tcp --permanent"
          not_if "firewall-cmd --list-port | egrep -i  '\\b#{one_port}/tcp'"
          notifies :reload, 'service[firewalld]', :immediately
          action :run
        end
      end

      f_all_slavenames().each do |one_slavename|
        slave_secret = f_slave_secret(one_slavename)
        execute "config slave #{one_slavename}" do
          command "#{jboss_eap_dir}/bin/add-user.sh -u #{one_slavename} -r ManagementRealm -cw -p '#{slave_secret}'#{version < 6.4 ? ' --silent' : ''}"
          action :run
          not_if "egrep -q '\\b#{one_slavename}\\b' #{configuration_dir}/mgmt-users.properties"
          sensitive false
        end
      end
      
      ruby_block 'call_me_back_action:take_snapshot' do
        block do
          action_take_snapshot
        end
        action :run
      end

      if major_version > 6
        exec_cli_resource 'jboss_host_controller_setup' do
          live_stream true
          echo_command true
          template 'setup.cli.controller.erb'
          host_config_file host_config_file
          domain_config_file domain_config_file
          run_offline true
          major_version major_version
          offline_start false
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
          template_variables(
            host_config_file: host_config_file,
            domain_config_file: domain_config_file,
            is_master: true,
            truststore_secret: truststore_secret,
            truststore_base_dir: truststore_dir,
            master_ssl_keystore: master_ssl_keystore,
            https_truststore_path: https_truststore_path,
            domain_name: domain_name,
            enable_native_9999: lowest_version_on_domain < 7
          )
        end

        ruby_block 'call_me_back_action:init_vault_keystore' do
          block do
            action_init_vault_keystore
          end
          action :run
        end

        if lowest_version_on_domain < 7
          exec_cli_resource 'jboss_eap6_compatible_sockets' do
            live_stream true
            echo_command true
            template 'eap6-compatible.cli.erb'
            host_config_file host_config_file
            domain_config_file domain_config_file
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
            run_offline !f_is_service_active(service_name)
            major_version major_version
            offline_start !f_is_service_active(service_name)
            action :apply
          end
        end
      else
        log 'For host controllers < 7 bring up before profile'
        
        jboss_eap_xml 'config master xml' do
          host_config_file host_config_file
          domain_config_file domain_config_file
          configuration_dir configuration_dir
          domain_version domain_version
          version version
          action :config_master
        end

        jboss_eap_xml 'pre-config domain xml' do
          domain_config_file domain_config_file
          configuration_dir configuration_dir
          domain_version domain_version
          domain_name domain_name
          action :preconfig_domain
        end

        
        
      end

      profile_idx = 0
      profile_host_exclude = {}
      profiles_cfg.each_pair do |profile_name, one_profile_cfg|
        profile_version = f_profile_version(one_profile_cfg)
        log "========================================================================="
        log "========================================================================="
        log "========================================================================="
        log "PROFILE VERSION: #{profile_version}"
        log "========================================================================="
        log "========================================================================="
        if profile_version < 7
           profile_tmp_content = "/tmp/profile-#{profile_name}-v#{profile_version}"

          template profile_tmp_content do
            source "eap#{profile_version}-profile.txt.erb"
            owner 'root'
            group 'root'
            mode '0755'
            action :create
            variables(
              webservice_fqdn: f_profile_webservice_fqdn(one_profile_cfg),
              profile_name: profile_name,
              use_local_hb_cache: f_use_local_hibernate_cache(one_profile_cfg),
              use_local_ejb_cache: f_use_local_ejb_cache(one_profile_cfg),
              use_local_web_cache: f_use_local_web_cache(one_profile_cfg),
              use_local_srv_cache: f_use_local_server_cache(one_profile_cfg),
              enable_sso: f_enable_sso(one_profile_cfg)
            )
          end

          jboss_eap_xml "include profile #{profile_name} to #{domain_config_file}" do
            action :add_profile
            profile_content lazy { IO.read(profile_tmp_content) }
            domain_content lazy { IO.read("#{configuration_dir}/#{domain_config_file}") }
            profile_name profile_name
            configuration_dir configuration_dir
            domain_config_file domain_config_file            
          end
          if domain_version.floor > 6
            cli_command = "if (outcome == \"success\") of /profile=#{profile_name}/subsystem=bean-validation:read-resource, "
            cli_command = "#{cli_command}/profile=#{profile_name}/subsystem=bean-validation:remove, end-if,"
            cli_command = "#{cli_command}/profile=#{profile_name}/subsystem=weld:write-attribute(name=require-bean-descriptor,value=true),"
            cli_command = "#{cli_command}/profile=#{profile_name}/subsystem=weld:write-attribute(name=non-portable-mode,value=true)"
            exec_cli_resource cli_command do
              live_stream true
              run_offline major_version > 6
              echo_command major_version > 6
              major_version major_version
              host_config_file host_config_file
              domain_config_file domain_config_file
              jboss_owner f_jboss_owner()
              jboss_group f_jboss_group()
              action :apply
            end
          end
        else
          exec_cli_resource "configure profile #{profile_name}" do
            template 'setup.cli.profile.erb'
            action :apply
            run_offline major_version > 6  && !f_is_service_active(service_name)
            major_version major_version
            offline_start major_version > 6
            host_config_file host_config_file
            domain_config_file domain_config_file
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
            template_variables(
              host_config_file: host_config_file,
              domain_config_file: domain_config_file,
              master_address: node['ipaddress'],
              cluster_cfg_name_prefix: f_cluster_cfg_name_prefix(profile_name),
              mod_cluster_port: cluster_port,
              cluster_address_list: f_profile_cluster_address(one_profile_cfg),
              webservice_fqdn: f_profile_webservice_fqdn(one_profile_cfg),
              undertow_buffer_size: f_profile_undertow_buffer_size(one_profile_cfg),
              source_profile_name: f_src_profile_name(one_profile_cfg),
              new_profile_name: profile_name,
              domain_name: domain_name,
              is_remote_log: is_remote_log,
              logserver_addr: logserver_addr,
              logserver_port: logserver_port,
              logserver_protocol: logserver_protocol,
              log_tag: f_profile_log_tag(profile_name, one_profile_cfg),
              enable_activemq: f_enable_activemq(one_profile_cfg),
              activemq_pass: f_activemq_pass(one_profile_cfg),
              use_local_hb_cache: f_use_local_hibernate_cache(one_profile_cfg),
              use_local_ejb_cache: f_use_local_ejb_cache(one_profile_cfg),
              use_local_web_cache: f_use_local_web_cache(one_profile_cfg),
              use_local_srv_cache: f_use_local_server_cache(one_profile_cfg),
              enable_sso: f_enable_sso(one_profile_cfg)
            )
          end
        end

        if profile_version != domain_version && domain_version > 6.4
          v_legacy_server_groups = f_legacy_server_groups(one_profile_cfg)
          if !v_legacy_server_groups.nil? && v_legacy_server_groups.any?
            v_profile_version_str = profile_version.to_s.eql?('6.4') ? "#{profile_version.to_s.gsub('.','')}z" : profile_version.to_s.gsub('.','')
            legcay_complete_list = profile_host_exclude.fetch(v_profile_version_str, []) + v_legacy_server_groups
            profile_host_exclude = profile_host_exclude.merge({ "#{v_profile_version_str}" => legcay_complete_list.uniq })
            log profile_host_exclude.to_s
            v_host_exclude_command = "/host-exclude=EAP#{v_profile_version_str}:write-attribute(name=active-server-groups,value=#{legcay_complete_list})"
            exec_cli_resource v_host_exclude_command do
              live_stream true
              run_offline major_version > 6
              echo_command major_version > 6
              major_version major_version
              host_config_file host_config_file
              domain_config_file domain_config_file
              jboss_owner f_jboss_owner()
              jboss_group f_jboss_group()
              action :apply
            end
          end
        elsif profile_version != domain_version
          raise 'only domain > 6.4 tested in mixed version configuration'
        end
      end

      log f_jboss_role_mappings().to_h.to_s

      ruby_block 'call_me_back_action:setup_ldap' do
        block do
          action_setup_ldap
        end
        action :run
        only_if { f_is_ldap_auth() }
      end

      ruby_block 'call_me_back_action:setup_rbac' do
        block do
          action_setup_rbac
        end
        action :run
        only_if { f_is_rbac() }
      end
      
      ruby_block 'call_me_back_action:setup_master_cli' do
        block do
          action_setup_cli
        end
        action :run
      end
    end

    action :init_vault_keystore do
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      version = new_resource.version
      service_name = new_resource.service_name

      if version > 7.0
        exec_cli_resource 'JBoss VAULT Init' do
          cfg_vault_cmd = "try, #{f_init_vault()}, catch, echo IhJaTaVa, end-try"
          sensitive true
          cli_commands cfg_vault_cmd
          host_config_file host_config_file
          domain_config_file domain_config_file
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          run_offline !f_is_service_active(service_name)
          action :apply
        end
      end
    end

    action :setup_cli do
      domain_config_file = new_resource.domain_config_file
      host_config_file = new_resource.host_config_file
      truststore_dir = new_resource.truststore_dir
      jboss_eap_dir = new_resource.jboss_eap_dir
      master_ipaddress = new_resource.master_ipaddress
      major_version = new_resource.major_version
      version = new_resource.version
      master_ssl_keystore = f_master_ssl_keystore()
      is_master = new_resource.is_master
      my_cert_path = f_my_cert_path()
      jbcli_cert_alias = node['fqdn']
      jb_cli_trust_str_path = "#{truststore_dir}/jboss-cli-trust.jks"
      jbcli_trust_str_pswd = f_jbosscli_secret()
      was_updated_filename = '/tmp/my-cert-update.txt'
      
      if major_version > 6 && is_master
        get_certificate 'get my certificate' do
          address node['hostname']
          port 9993
          cert_path my_cert_path
          keystore master_ssl_keystore
          domain_config_file domain_config_file
          host_config_file host_config_file
          update_control true
          was_updated_filename was_updated_filename
          ca_trust_update false
          action :from_cli_offline
        end

        keytool_manage "Importar Certificado #{my_cert_path} para jboss_cli" do
          cert_alias jbcli_cert_alias
          action :importcert
          file my_cert_path
          keystore jb_cli_trust_str_path
          storepass jbcli_trust_str_pswd
        end

        execute 'jboss_cli_key_store_perm' do
          command "chmod 640 #{jb_cli_trust_str_path}"
          action :run
        end

        execute 'Change Cli Trust Store Owner' do
          command "chown #{f_jboss_owner()}.#{f_jboss_group()} #{jb_cli_trust_str_path}"
          action :run
        end
      end

      directory "#{jboss_eap_dir}/.jboss-cli-history" do
        owner f_jboss_owner()
        group 'root'
        mode '0750'
        action :create
      end

      template "#{jboss_eap_dir}/bin/jboss-cli.xml" do
        source 'jboss-cli.xml.erb'
        owner f_jboss_owner()
        group f_jboss_group()
        mode '0640'
        action :create
        variables(
          alias: jbcli_cert_alias,
          keystore: jb_cli_trust_str_path,
          storepass: jbcli_trust_str_pswd,
          major_version: major_version,
          version: version,
          is_master: is_master,
          jboss_eap_dir: jboss_eap_dir          
          )
      end
    end

    action :setup_ldap do
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      credstore_dir = new_resource.credstore_dir
      is_master = new_resource.is_master
      truststore_dir = new_resource.truststore_dir
      domain_version = new_resource.domain_version
      version = new_resource.version
      truststore_secret = f_truststore_secret()
      ldap_credstore_name = f_ldap_credstore_name()
      ldap_credstore_pw = f_ldap_credstore_pw()
      ldap_filter_base_dn = f_ldap_filter_base_dn()
      ldap_search_base_dn = f_ldap_search_base_dn()
      ldap_principal = f_ldap_principal()
      ldap_principal_pw = f_ldap_principal_pw()
      ldap_server_url = f_ldap_server_url()
      ldap_server_address = f_ldap_server_address()
      ldap_port = 636
      ldap_credstore_path = "#{credstore_dir}/#{ldap_credstore_name}.jceks"
      ldap_cert_path = f_ldap_cert_path()
      jboss_user_roles = f_jboss_user_roles()
      jboss_role_mappings = f_jboss_role_mappings()
      ldap_srv_cert_update = '/tmp/ldap.update'
      ldap_cred_alias = 'ldapjboss-pw'
      ldap_truststore_path = f_ldap_truststore_path()
      
      if version > 7.0
        exec_cli_resource 'JBoss LDAP Credential Store' do
          ldap_setup_credstore_cmd = "if (outcome != success) of  /host=#{node['hostname']}/subsystem=elytron/credential-store=#{ldap_credstore_name}:read-resource,"
          ldap_setup_credstore_cmd = "#{ldap_setup_credstore_cmd} /host=#{node['hostname']}/subsystem=elytron/credential-store=#{ldap_credstore_name}:add("
          ldap_setup_credstore_cmd = "#{ldap_setup_credstore_cmd}location=#{ldap_credstore_path}, credential-reference={"
          ldap_setup_credstore_cmd = "#{ldap_setup_credstore_cmd}clear-text=#{ldap_credstore_pw}}, create=true), end-if"
          sensitive true
          cli_commands ldap_setup_credstore_cmd
          host_config_file host_config_file
          domain_config_file domain_config_file
          run_offline true
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
        end

        exec_cli_resource 'Add LDAP Passowrd to Credential Store' do
          add_ldap_pwd2str_cmd = "try, /host=#{node['hostname']}/subsystem=elytron/credential-store=#{ldap_credstore_name}:add-alias("
          add_ldap_pwd2str_cmd = "#{add_ldap_pwd2str_cmd}alias=#{ldap_cred_alias}, secret-value=\"#{ldap_principal_pw}\")"
          add_ldap_pwd2str_cmd = "#{add_ldap_pwd2str_cmd}, catch, echo ja instalado ou erro. Se liga ahi, finally, echo fim, end-try"
          sensitive true
          cli_commands add_ldap_pwd2str_cmd
          host_config_file host_config_file
          domain_config_file domain_config_file
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          run_offline true
          action :apply
        end
       end

      get_certificate 'get ldap server certificate' do
        address ldap_server_address
        port ldap_port
        cert_path ldap_cert_path
        update_control true
        was_updated_filename ldap_srv_cert_update
        ca_trust_update true
        action :do
      end

      if version > 7.0
        exec_cli_resource 'Setup ldap' do
          template 'setup.ldap.cli.erb'
          host_config_file host_config_file
          domain_config_file domain_config_file
          run_offline true
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
          template_variables(
            ldap_url: ldap_server_url,
            ldap_principal: ldap_principal,
            ldap_filter_base_dn: ldap_filter_base_dn,
            ldap_search_base_dn: ldap_search_base_dn,
            ldap_credential_store_name: ldap_credstore_name,
            ldap_cred_alias:  ldap_cred_alias,
            ldap_cert_path: ldap_cert_path,
            truststore_secret: truststore_secret,
            ldap_truststore_path: ldap_truststore_path,
            jboss_user_roles: jboss_user_roles,
            jboss_role_mappings: jboss_role_mappings,
            was_cert_updated: lazy { ::File.exist? ldap_srv_cert_update }
          )
        end
      else
        keytool_manage "Importar Certificado #{ldap_cert_path} para ldap" do
          cert_alias ldap_server_address
          action :importcert
          file ldap_cert_path
          keystore ldap_truststore_path
          storepass truststore_secret
        end
      end
    end

    action :setup_rbac do
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      is_master = new_resource.is_master
      domain_version = new_resource.domain_version
      version = new_resource.version
      jboss_user_roles = f_jboss_user_roles()
      jboss_role_mappings = f_jboss_role_mappings()
      service_name = new_resource.service_name
      
      if version > 7.0 && is_master && f_is_rbac()
        exec_cli_resource 'Setup Rbac' do
          template 'setup.rbac.cli.erb'
          host_config_file host_config_file
          domain_config_file domain_config_file
          run_offline !f_is_service_active(service_name)
          sensitive false
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
          template_variables(
            jboss_user_roles: jboss_user_roles,
            jboss_role_mappings: jboss_role_mappings,
            version: version,
          )
        end
      elsif f_is_service_active(service_name) && is_master && f_is_rbac()
        exec_cli_resource 'Setup Rbac' do
          live_stream true
          template 'setup.rbac.cli.erb'
          host_config_file host_config_file
          domain_config_file domain_config_file
          run_offline false
          sensitive false
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
          template_variables(
            jboss_user_roles: jboss_user_roles,
            jboss_role_mappings: jboss_role_mappings,
            version: version,
          )
        end
      end
    end

    action :setup_slave do
      # name = new_resource.name
      jboss_eap_dir = new_resource.jboss_eap_dir
      master_ipaddress = new_resource.master_ipaddress
      master_fqdn = new_resource.master_fqdn
      cluster_address = f_my_cluster_addresses()
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      configuration_dir = new_resource.configuration_dir
      master_cert_path = new_resource.master_cert_path
      domain_name = new_resource.domain_name
      truststore_dir = new_resource.truststore_dir
      is_master = new_resource.is_master
      # service_name = new_resource.service_name
      # trust_store_base_dir = new_resource.truststore_dir
      truststore_secret = f_truststore_secret()
      slave_secret = f_slave_secret()
      slave_secret_b64 = f_slave_secret_b64()
      my_version = new_resource.version
      major_version = new_resource.major_version

      if f_has_jmx_zabbix_conf()
        zabbix_user = f_zabbix_user()
        zabbix_password = f_zabbix_password()
        execute "config zabbix #{zabbix_user}" do
          command "#{jboss_eap_dir}/bin/add-user.sh -u #{zabbix_user} -a -r ApplicationRealm -cw -p '#{zabbix_password}'#{my_version < 6.4 ? ' --silent' : ''}"
          action :run
          not_if "egrep -q '\\b#{zabbix_user}\\b' #{configuration_dir}/application-users.properties"
          sensitive false
        end
      end

      addrs_2_trust =  f_has_jmx_zabbix_conf() ? [f_zabbix_server_address()] + [master_ipaddress] + cluster_address : [master_ipaddress] + cluster_address
      pvt_if_fulladdr = f_private_fulladdress()
      has_pvt_jg_nw = pvt_if_fulladdr.nil? ? false : true
      pvt_if_ipaddr = has_pvt_jg_nw ? f_private_ipaddress(pvt_if_fulladdr) : nil
      pvt_if_ip_prefixlen = has_pvt_jg_nw ? f_private_ip_prefixlen(pvt_if_fulladdr) : 0

      if has_pvt_jg_nw and major_version > 6
        last_oct_addr = pvt_if_ipaddr.delete_prefix(EAP::PVT_JGROUPS_NETWORK).to_i
        nw_aux = pvt_if_ip_prefixlen.to_i - 24
        if nw_aux < 4 # too large network for us
          log 'restrinja mais o número de possíveis servidores na sub-rede, não trabalhamos com clusters com essa quantidade de membros por aqui.'
          log "ip/prefixlen: #{pvt_if_ipaddr}/#{pvt_if_ip_prefixlen}"
          log 'Continuando configuração sem interface privada - jgroups não funcionará'
          has_pvt_jg_nw = false
        else
          las_oct_mask = 256 - (8 - nw_aux)**2
          pvt_network_address = "#{EAP::PVT_JGROUPS_NETWORK}#{las_oct_mask & last_oct_addr}"

          addrs_2_trust << "#{pvt_network_address}/#{pvt_if_ip_prefixlen}"
        end
      elsif major_version < 7
        jgroups_hosts = f_my_jgroups_hosts()
        jgroups_hosts.each do |jg_member|
          member_ip = jg_member.split(':')[0]
          member_port = jg_member.split(':')[1]
          if !member_ip.eql?("#{node['ipaddress']}/32")
            v_firewall_cmd = 'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="'
            v_firewall_cmd = "#{v_firewall_cmd}#{member_ip}\" port protocol=\"tcp\" port=\"#{member_port}\" accept'"

            execute "open jgroup port #{member_port} to #{member_ip}" do
              command v_firewall_cmd
              action :run
              not_if "firewall-cmd --list-rich-rules --permanent | grep #{member_ip} | egrep -q '\\b#{member_port}\\b'"
              notifies :reload, 'service[firewalld]', :immediately
            end
            
          end
        end
      end

      addrs_2_trust.each do |trusted_addr|
        trusted_ip = trusted_addr.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}.*/) ? trusted_addr : f_resolve_name(trusted_addr)
        execute 'firewalld-cmd ips to trust' do
          command "firewall-cmd --add-source=#{(trusted_ip.include? '/') ? trusted_ip : (trusted_ip + '/32')} --zone=trusted --permanent"
          action :run
          not_if "firewall-cmd --list-all --zone=trusted --permanent | grep -q #{trusted_ip}"
          notifies :reload, 'service[firewalld]', :immediately
        end
      end

      f_my_server_groupnames().each do |one_srv_grp_name|
        v_server_name = "#{one_srv_grp_name}#{f_my_server_id_suffix()}"
        link "#{f_sys_log_base_dir()}/#{v_server_name}" do
          to f_server_log_dir(v_server_name)
          ignore_failure true
        end
      end

      master_cert_path_tmp_file = "/tmp/#{master_fqdn}.crt"
      master_cert_path_update = '/tmp/master_cert_path_update'

      get_certificate 'get master certificate' do
        address master_fqdn
        port 9993
        cert_path master_cert_path
        update_control true
        was_updated_filename master_cert_path_update
        ca_trust_update false
        action :do
        not_if { major_version < 7 }
      end

      ruby_block 'call_me_back_action:setup_cli' do
        block do
          action_setup_cli
        end
        action :run
      end

      ruby_block 'call_me_back_action:take_snapshot' do
        block do
          action_take_snapshot
        end
        action :run
      end

      if major_version >= 7
        exec_cli_resource 'jboss_host_controller_setup' do
          live_stream true
          echo_command true
          template 'setup.cli.controller.erb'
          host_config_file host_config_file
          domain_config_file domain_config_file
          run_offline true
          offline_start false
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
          template_variables(
            host_config_file: host_config_file,
            domain_config_file: domain_config_file,
            master_address: master_ipaddress,
            slave_secret: slave_secret,
            slave_secret_b64: slave_secret_b64,
            is_master: false,
            master_fqdn: master_fqdn,
            master_cert_path: master_cert_path,
            truststore_secret: truststore_secret,
            truststore_base_dir: truststore_dir,
            has_pvt_jg_nw: has_pvt_jg_nw,
            pvt_if_ipaddr: pvt_if_ipaddr,
            enable_unsecure_interface: f_has_full_server(),
            update_master_cert: lazy { ::File.exist? master_cert_path_update },
            domain_name: domain_name
          )
        end

        ruby_block 'call_me_back_action:init_vault_keystore' do
          block do
            action_init_vault_keystore
          end
          action :run
        end

#        ruby_block 'call_me_back_action:setup_ldap' do
#          block do
###            action_setup_ldap
#          end
#          action :run
#          only_if { f_is_ldap_auth() }
#        end
      else
        jboss_eap_xml "Config XML on EAP #{f_my_version()}" do
          action :config_slave
          host_config_file host_config_file
          domain_config_file domain_config_file
          configuration_dir configuration_dir
          log_dir log_dir
          master_ipaddress master_ipaddress
          slave_secret slave_secret
          slave_secret_b64 slave_secret_b64
          is_master false
          master_fqdn master_fqdn
          master_cert_path master_cert_path
          truststore_secret truststore_secret
          truststore_dir truststore_dir
          has_pvt_jg_nw has_pvt_jg_nw
          version my_version
          pvt_if_ipaddr pvt_if_ipaddr
          domain_name domain_name
        end
      end
    end

    action :setup do
      jboss_eap_dir = new_resource.jboss_eap_dir
      major_version = new_resource.major_version
      version = new_resource.version
      domain_version = new_resource.domain_version
      domain_name = new_resource.domain_name
      configuration_dir = new_resource.configuration_dir
      log_dir = new_resource.log_dir
      domain_config_file = new_resource.domain_config_file
      host_config_file = new_resource.host_config_file
      is_master = new_resource.is_master
      service_name = new_resource.service_name
      force_setup = new_resource.force_setup
      is_legacy_eap = (version < domain_version)
      jboss_install_home_dir = f_install_home_dir(major_version)

      template f_install_service_conf_path(major_version) do
        source 'eap-domain.conf.erb'
        owner 'root'
        group 'root'
        mode '0644'
        action :create
        variables(
          host_config_file: host_config_file,
          domain_config_file: domain_config_file,
          version: version,
          jboss_install_home_dir: jboss_install_home_dir,
          log_path: log_dir,
          init_script: f_init_script(),
          is_rpm: f_is_rpm_install(),
          jboss_owner: f_jboss_owner(),
          jboss_group: f_jboss_group()
        )
      end

      template "/usr/lib/systemd/system/#{service_name}.service" do
        source 'eap-domain.service.erb'
        owner 'root'
        group 'root'
        mode '0644'
        action :create
        variables(
          service_name: service_name,
          version: version,
          major_version: major_version,
          init_script: f_init_script(),
          is_rpm: f_is_rpm_install()
        )
      end

      execute 'systemctl daemon-reload' do
        command 'systemctl daemon-reload'
        action :nothing
        subscribes :run, "template[/usr/lib/systemd/system/#{service_name}.service]", :immediately
      end

      service 'firewalld' do
        action [:enable, :start]
      end

      f_init_vault_reqs()

      if major_version > 6 
        file "#{configuration_dir}/#{domain_config_file}" do
          content lazy { IO.read("#{configuration_dir}/domain.xml") }
          action :create
          owner f_jboss_owner()
          group f_jboss_group()
          mode '0664'
          not_if "test -f #{configuration_dir}/#{domain_config_file}"
        end

        file "#{configuration_dir}/#{host_config_file}" do
          content lazy { IO.read("#{configuration_dir}/host-#{is_master ? 'master' : 'slave'}.xml") }
          action :create
          owner f_jboss_owner()
          group f_jboss_group()
          mode '0664'
          not_if "test -f #{configuration_dir}/#{host_config_file}"
        end
      end

      ruby_block "call_me_back_action:setup_#{is_master ? 'master' : 'slave'}" do
        block do
          if is_master
            action_setup_master
          else
            action_setup_slave
          end
        end
        action :run
        not_if f_is_service_active(service_name) && !force_setup
      end

      ruby_block "call_me_back_action:online_#{is_master ? 'master' : 'slave'}" do
        block do
          if is_master
            action_online_master
          else
            action_online_slave
          end
        end
        action :run
        not_if f_is_service_active(service_name) && !force_setup
      end
      
    end

    action :online_master do
      name = new_resource.name
      started_code = new_resource.started_code
      service_name = new_resource.service_name
      jboss_eap_dir = new_resource.jboss_eap_dir
      log_dir = new_resource.log_dir
      profiles_cfg = new_resource.profiles_cfg
      module_dir = f_modules_dir()
      version = new_resource.version
      major_version = new_resource.major_version
      ldap_jboss_acc = f_ldap_principal_acc()
      ldap_jboss_pw = f_ldap_principal_pw()
      cert_path = f_my_cert_path()
      domain_system_properties = new_resource.domain_system_properties
      
      f_service_up(service_name, started_code, "#{log_dir}/console.log")

      service service_name do
        action :enable
      end

      file "#{jboss_eap_dir}/first_config_run" do
        content 'service successfully started and enabled mark'
        owner 'root'
        group 'root'
        mode '0755'
        action :create
      end

      if domain_system_properties.any?
        cli_resource "system-properties" do
          desired_state domain_system_properties
          resource_type 'system-property'
          eap_version version
          cert_path cert_path
          username ldap_jboss_acc
          userpw ldap_jboss_pw      
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
        end
      end

      profiles_cfg.each_pair do |profile_name, one_profile_cfg|
        v_server_groups = f_profile_server_groups(one_profile_cfg)
        v_desired_out_state = f_desired_outbound_state(profile_name, one_profile_cfg)
        ['full-ha-sockets', 'ha-sockets'].each do |one_socket_binding_group|
          cli_resource "#{profile_name}-#{one_socket_binding_group}-remote-destination-outbound-socket-binding" do
            desired_state v_desired_out_state
            resource_address  "/socket-binding-group=#{one_socket_binding_group}"
            resource_type 'remote-destination-outbound-socket-binding'
            eap_version version
            cert_path cert_path
            username ldap_jboss_acc
            userpw ldap_jboss_pw
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
          end
        end

        v_desired_cluster_state = f_desired_modcluster_state(profile_name, one_profile_cfg)
        cli_resource "#{profile_name}-mod_cluster_config" do
          profile_name profile_name
          desired_state v_desired_cluster_state
          resource_address  "/profile=#{profile_name}/subsystem=modcluster"
          resource_type f_profile_version(one_profile_cfg) < 7 ? 'mod-cluster-config' : 'proxy'
          eap_version version
          cert_path cert_path
          username ldap_jboss_acc
          userpw ldap_jboss_pw
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
        end

        exec_cli_resource "#{profile_name}-mod_cluster_load_metrics" do
          template 'setup_modcluster.cli.erb'
          live_stream true
          echo_command major_version > 6
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          template_variables(
            profile_name: profile_name,
            jboss_version: version  
          )
        end

        exec_cli_resource "#{profile_name}-webservice_config" do
          template 'setup_webservices.cli.erb'
          live_stream true
          echo_command major_version > 6
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          template_variables(
            profile_name: profile_name,
            jboss_version: version,
            webservice_fqdn: f_profile_webservice_fqdn(one_profile_cfg)
          )
        end

        v_srv_grps_desired_state = f_remove_keys(v_server_groups, ['public-http','enable-gclog','heap-size', 'max-heap-size', 'permgen-size', 'max-permgen-size', 'system-properties','slave-hosts', 'enable-debug', 'jvm-options'])

        cli_resource 'server-groups' do
          profile_name profile_name
          desired_state v_srv_grps_desired_state
          resource_type 'server-group'
          eap_version version
          cert_path cert_path
          username ldap_jboss_acc
          userpw ldap_jboss_pw
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
        end

        v_server_groups.each_pair do |srv_group_name, one_srv_grp_cfg|
          jvms_desired_state = f_desired_jvm(srv_group_name, one_srv_grp_cfg)

          cli_resource "jvm-#{srv_group_name}" do
            profile_name profile_name
            desired_state jvms_desired_state
            resource_address "/server-group=#{srv_group_name}"
            resource_type 'jvm'
            eap_version version
            cert_path cert_path
            username ldap_jboss_acc
            userpw ldap_jboss_pw
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
          end

          if one_srv_grp_cfg.has_key? 'system-properties'
            cli_resource "server-group-#{srv_group_name}-system-properties" do
              profile_name profile_name
              desired_state f_system_properties(one_srv_grp_cfg)
              resource_address "/server-group=#{srv_group_name}"
              resource_type 'system-property'
              eap_version version
              cert_path cert_path
              username ldap_jboss_acc
              userpw ldap_jboss_pw      
              jboss_owner f_jboss_owner()
              jboss_group f_jboss_group()
            end
          end
        end

        v_jdbc_drivers = f_modules_cfg().select { |_k,v| v['group'].nil? || v['group'].empty? || v['group'].casecmp('jdbc') }
        v_jdbc_drivers_desired_state = f_remove_keys(v_jdbc_drivers, ['file', 'group'])
        
        cli_resource 'jdbc-drivers' do
          profile_name profile_name
          desired_state v_jdbc_drivers_desired_state
          resource_address "/profile=#{profile_name}/subsystem=datasources"
          resource_type 'jdbc-driver'
          eap_version version
          cert_path cert_path
          username ldap_jboss_acc
          userpw ldap_jboss_pw    
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
        end
        
        v_data_sources = f_profile_datasources(one_profile_cfg)

        v_xa_data_sources = f_profile_xa_datasources(one_profile_cfg)
        #additional legacy sec domains
        f_profile_sec_domains(one_profile_cfg).each_pair do |sec_domain_name, one_sec_domain_cfg|
          v_domain_options = f_sec_domain_options(one_sec_domain_cfg)
          v_sd_module_options = v_domain_options.any? ? v_domain_options.collect {|option_name,option_value| "\"#{option_name}\"=\"#{option_value}\"" } : []

          exec_cli_resource "security-domain-#{sec_domain_name}" do
            sensitive true
            echo_command major_version > 6
            major_version major_version
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
            template 'securitydomains.cli.erb'
            template_variables(
              profile_name: profile_name,
              name: sec_domain_name,
              code: f_sec_domain_code(one_sec_domain_cfg),
              flag: f_sec_domain_flag(one_sec_domain_cfg),
              module_options: v_sd_module_options
            )
          end
        end

        v_ds_desired_state = f_desired_state_datasource(v_data_sources)#, 'Encrypt')
        cli_resource 'datasources' do
          profile_name profile_name
          desired_state v_ds_desired_state
          resource_address "/profile=#{profile_name}/subsystem=datasources"
          resource_type 'data-source'
          eap_version version
          cert_path cert_path
          username ldap_jboss_acc
          userpw ldap_jboss_pw
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
        end

        #v_xa_ds_desired_state = f_remove_keys(v_xa_data_sources, ['xa-datasource-properties'])
        v_xa_ds_desired_state = f_desired_state_xa_datasource(v_xa_data_sources)
        cli_resource 'xa-datasources' do
          profile_name profile_name
          desired_state v_xa_ds_desired_state
          resource_address "/profile=#{profile_name}/subsystem=datasources"
          resource_type 'xa-data-source'
          eap_version version
          cert_path cert_path
          username ldap_jboss_acc
          userpw ldap_jboss_pw
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
        end

        v_xa_data_sources.each_pair do |xa_ds_name, one_xa_ds_config|
          cli_resource 'xa-datasources-properties' do
            profile_name profile_name
            desired_state one_xa_ds_config['xa-datasource-properties']
            resource_address "/profile=#{profile_name}/subsystem=datasources/xa-data-source=#{xa_ds_name}"
            resource_type 'xa-datasource-properties'
            eap_version version
            cert_path cert_path
            username ldap_jboss_acc
            userpw ldap_jboss_pw
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
          end
        end

        #v_syslog_handlers_ds_state = f_profile_syslog_handler(profile_name, one_profile_cfg)
        v_syslog_handlers_ds_state = f_profile_log_handler(profile_name, one_profile_cfg)
        v_syslog_handlers_ds_state.each_pair do |handler_type, handler_type_cfg|
          cli_resource 'syslog-handlers' do
            profile_name profile_name
            desired_state handler_type_cfg
            resource_address "/profile=#{profile_name}/subsystem=logging"
            resource_type handler_type
            eap_version version
            cert_path cert_path
            username ldap_jboss_acc
            userpw ldap_jboss_pw
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
          end

          handler_type_cfg.each_pair do |handler_name, _one_handler_cfg|
            exec_cli_resource 'add syslog handler'  do
              cli_commands "try, /profile=#{profile_name}/subsystem=logging/root-logger=ROOT:add-handler(name=#{handler_name}), catch, #{version < 6.4 ? 'pwd' : 'echo Ihjatava'}, end-try"
              live_stream true
              echo_command major_version > 6
              major_version major_version
              jboss_owner f_jboss_owner()
              jboss_group f_jboss_group()
            end
          end
        end

        if f_has_jmx_zabbix_conf()
          cli_resource "#{profile_name}-jmx" do
            profile_name profile_name
            desired_state f_jmx_desired()
            resource_address "/profile=#{profile_name}/subsystem=jmx"
            resource_type 'remoting-connector'
            eap_version version
            cert_path cert_path
            username ldap_jboss_acc
            userpw ldap_jboss_pw
            jboss_owner f_jboss_owner()
            jboss_group f_jboss_group()
          end
        end
      end

    end

    action :online_slave do
      started_code = new_resource.started_code
      service_name = new_resource.service_name
      major_version = new_resource.major_version
      jboss_eap_dir = new_resource.jboss_eap_dir
      log_dir = new_resource.log_dir
      profiles_cfg = new_resource.profiles_cfg

      f_service_up(service_name, started_code, "#{log_dir}/console.log")

      service service_name  do
        action :enable
      end

      file "#{jboss_eap_dir}/first_config_run" do
        content 'service successfully started and enabled mark'
        owner 'root'
        group 'root'
        mode '0755'
        action :create
      end

      f_my_server_groups().each_pair do |profile_name, server_groups|

        v_prof_datasources = f_profile_datasources(profiles_cfg.fetch(profile_name.to_s))

        f_setup_vault_ds_passwords(v_prof_datasources)

        server_groups.each_pair do |_srv_grp_name, one_srv_grp_cfg|
          if f_enable_srv_group_debug(one_srv_grp_cfg)
            v_debug_port = f_srv_group_debug_port(one_srv_grp_cfg)
            execute "OpenConsole Port #{v_debug_port}" do
              command "firewall-cmd --add-port=#{v_debug_port}/tcp --permanent"
              not_if "firewall-cmd --list-port | egrep -i  '\\b#{v_debug_port}/tcp'"
              notifies :reload, 'service[firewalld]', :immediately
              action :run
            end
          else
            v_debug_port = f_srv_group_debug_port(one_srv_grp_cfg)
            execute "OpenConsole Port #{v_debug_port}" do
              command "firewall-cmd --remove-port=#{v_debug_port}/tcp --permanent"
              only_if "firewall-cmd --list-port --permanent | egrep -i  '\\b#{v_debug_port}/tcp'"
              action :run
            end

            execute "OpenConsole Port #{v_debug_port}" do
              command "firewall-cmd --remove-port=#{v_debug_port}/tcp"
              only_if "firewall-cmd --list-port | egrep -i  '\\b#{v_debug_port}/tcp'"
              action :run
            end
          end
          if f_has_full_source_profile(f_profiles()[profile_name])
            http_port = f_srv_group_http_port(one_srv_grp_cfg)
            if f_public_http(one_srv_grp_cfg)
              v_firewall_cmd = "firewall-cmd --permanent --zone=public --add-port=#{http_port}"
              execute "open http port #{http_port} to public" do
                command v_firewall_cmd
                action :run
                not_if "firewall-cmd --list-ports --permanent | egrep -q '\\b#{http_port}\\b'"
                notifies :reload, 'service[firewalld]', :immediately
              end
            else
              f_http_trust(one_srv_grp_cfg).each do |partner_source|
                v_firewall_cmd = 'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="'
                v_firewall_cmd = "#{v_firewall_cmd}#{partner_source}\" port protocol=\"tcp\" port=\"#{http_port}\" accept'"

                execute "open http port #{http_port} to #{partner_source}" do
                  command v_firewall_cmd
                  action :run
                  not_if "firewall-cmd --list-rich-rules --permanent | grep #{partner_source} | egrep -q '\\b#{http_port}\\b'"
                  notifies :reload, 'service[firewalld]', :immediately
                end
              end
              v_firewall_cmd = "firewall-cmd --permanent --zone=public --remove-port=#{http_port}"
              execute "open http port #{http_port} to public" do
                command v_firewall_cmd
                action :run
                only_if "firewall-cmd --list-ports --permanent | egrep -q '\\b#{http_port}\\b'"
                notifies :reload, 'service[firewalld]', :immediately
              end
            end
          end
        end

        exec_cli_resource "#{profile_name}-server_config" do
          template 'serverconfigs.cli.erb'
          template_variables(
            server_groups: server_groups,
            server_id_suffix: f_my_server_id_suffix(),
            tx_id_suffix: f_my_tx_id_suffix(),
            sys_log_base_dir: f_sys_log_base_dir()
          )
          live_stream true
          run_offline false
          echo_command major_version > 6
          major_version major_version
          ignore_failure false
          jboss_owner f_jboss_owner()
          jboss_group f_jboss_group()
          action :apply
        end
      end
    end

    action_class do
      include InfraEAP::Helper
      include InfraEAP::ConfHelper
    end
  end
end
