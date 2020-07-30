#
# Cookbook Name:: jboss-eap
# Recipe:: eap7
#
# Copyright 2020, TRF2
#
# All rights reserved - Do Not Redistribute
#
# --------------------- Atencao ---------------------
require 'json'
module InfraEAP
  module ConfHelper
    def f_init_script(p_major_version=f_my_mj_version())
      v_init_script_rpath = f_default_conf(p_major_version).fetch(:init_script, 'bin/domain.sh')
      "#{f_install_home_dir(p_major_version)}/#{v_init_script_rpath}"
    end

    def f_lowest_slave_version
      v_lowest_version = f_domain_version()

      f_legacy_slavenames().each do |slavename|
        v_aux_version = f_version(slavename)
        v_lowest_version = v_lowest_version < v_aux_version ? v_lowest_version : v_aux_version
      end

      v_lowest_version
    end

    def f_profile_version(p_one_profile_cfg)
      v_srv_groups = f_profile_server_groups(p_one_profile_cfg).select { |_k,v| v.fetch('slave-hosts',[]).any? }
      v_profile_version =  f_domain_version()
      if !v_srv_groups.nil? && v_srv_groups.any?
        v_srv_groups.each_pair do |_grp_name, one_grp_cfg|
          v_profile_version = f_version(one_grp_cfg.fetch('slave-hosts')[0])
          break
        end
      end

      v_profile_version
    end

    def f_legacy_server_groups(p_one_profile_cfg)
      v_srv_groups = []
      
      if f_profile_version(p_one_profile_cfg) < f_domain_version()
        v_srv_groups = f_profile_server_groups(p_one_profile_cfg).select { |_k,v| v.fetch('slave-hosts',[]).any? }.keys
      end

      v_srv_groups
    end

    def f_service_up(p_service_name, p_started_code, p_console_log_path)
      v_is_service_up = false
      v_is_active = f_is_service_active(p_service_name)

      if v_is_active
        v_dt_init = f_service_status_since_time(p_service_name)
        if v_dt_init == 0
          log 'erro ao verificar data de incialização do serviço, considerando como não ativo para que o setup seja realizado'
        # elsif ::Time.now.strftime('%Y%m%d%H%M%S').to_i - v_dt_init > 10000
        #  v_is_service_up = true
        else
          f_wait_service_start(p_service_name, p_started_code, p_console_log_path)
          v_is_service_up = true
        end
      else
          f_wait_service_start(p_service_name, p_started_code, p_console_log_path)
          v_is_service_up = true
      end
      v_is_service_up
    end

    def f_wait_service_start(p_service_name, p_started_code, p_console_log_path)

      service p_service_name do
        action :start
      end

      # v_dt_init = f_service_status_since_time(p_service_name)
      # espera entre 5 e 6 min min
      v_cmd = "DT_INI=$(systemctl status #{p_service_name} | grep Active | sed -e 's/^.*since [A-Z]\\{1\\}[a-z]\\{2\\} \\([0-9|-]* [0-9|:]*\\) .*;.*/\\1/g' -e 's/-\\|:\\| //g')"
      v_cmd = "#{v_cmd}; sleep 5; until grep -q '#{p_started_code}' #{p_console_log_path}; do echo 'Not started'; sleep 1; "
      v_cmd = "#{v_cmd} if [[ $(expr $(date '+%Y%m%d%H%M%S') - $DT_INI) -gt 600 ]]; then echo service start timed out; exit 1; fi; done "

      execute "wait_service_start: #{p_service_name} - #{p_console_log_path}" do
        command v_cmd
        action :run
        not_if "grep -q '#{p_started_code}' #{p_console_log_path}"
      end
    end

    def f_is_service_active(p_service_name)
      v_cmd = "systemctl is-active #{p_service_name}"
      v_is_active = response(v_cmd)

      v_is_active.strip.casecmp?('active')
    end

    def f_service_status_since_time(p_service_name)
      v_cmd = "systemctl status #{p_service_name} | grep Active | sed -e 's/^.*since [A-Z]\\{1\\}[a-z]\\{2\\} \\([0-9|-]* [0-9|:]*\\) .*;.*/\\1/g' -e 's/-\\|:\\| //g'"
      log v_cmd
      v_time = response(v_cmd).strip
      log v_time
      if v_time.empty?
        v_time = 0
      end

      v_time.to_i + 1
    end

    def f_cluster_cfg_name_prefix(p_profile_name)
      "#{p_profile_name}_bal"
    end

    def f_desired_outbound_state(p_profile_name, p_one_profile_cfg)
      cluster_idx = 0
      def_cluster_port = f_default_cluster_port()
      v_desired_outbound_state = {}

      f_profile_cluster_address(p_one_profile_cfg).each do |one_cluster_address|
        cluster_idx += 1
        item_cluster_cfg_name = "#{f_cluster_cfg_name_prefix(p_profile_name)}#{cluster_idx}"
        v_desired_outbound_state = v_desired_outbound_state.merge({"#{item_cluster_cfg_name}": {"host": "#{one_cluster_address}","port": "#{def_cluster_port}"}})
      end
      v_desired_outbound_state
    end

    def f_desired_modcluster_state(p_profile_name, p_one_profile_cfg)
      def_cluster_port = f_default_cluster_port()
      v_desired_mod_cluster_cfg = {}
      
      def_cluster_port = f_default_cluster_port()
      v_default_lb_group_name = "#{p_profile_name}Default"
      v_default_lb_group_name = v_default_lb_group_name.length > 20 ? v_default_lb_group_name[0..19] : v_default_lb_group_name
      v_default_balancer_name = "#{p_profile_name}Default"
      v_default_balancer_name = v_default_balancer_name.length > 40 ? v_default_balancer_name[0..39] : v_default_balancer_name

      if f_profile_version(p_one_profile_cfg) < 6.3
        v_proxy_list = f_profile_cluster_address(p_one_profile_cfg).map { |one_address| "#{one_address}:#{def_cluster_port}" }.join(',')
        v_desired_mod_cluster_cfg = {
                                      "configuration": {
                                        "connector": "ajp",
                                        "advertise": "false",
                                        "balancer": '${jboss.modcluster.balancer:' + v_default_balancer_name + '}',
                                        "load-balancing-group": '${jboss.modcluster.load-balancing-group:' + v_default_lb_group_name + '}',
                                        "excluded-contexts": "${jboss.modcluster.excluded-contexts:ROOT,invoker,jbossws,juddi,console}",
                                        "worker-timeout": "${jboss.modcluster.worker-timeout:-1}",
                                        "stop-context-timeout": "${jboss.modcluster.stop-context-timeout:10}",
                                        "node-timeout": "${jboss.modcluster.node-timeout:-1}",
                                        "socket-timeout":  "${jboss.modcluster.socket-timeout:20}",
                                        "ping": "${jboss.modcluster.ping:10}",
                                        "flush-wait": "${jboss.modcluster.flush-wait:-1}",
                                        "smax": "${jboss.modcluster.smax:-1}",
                                        "ttl": "${jboss.modcluster.ttl:-1}",
                                        "flush-packets": "${jboss.modcluster.flush-packets:false}",
                                        "auto-enable-contexts": "${jboss.modcluster.auto-enable-contexts:true}",
                                        "max-attempts": "${jboss.modcluster.max-attempts:1}",
                                        "sticky-session": "${jboss.modcluster.sticky-session:true}",
                                        "sticky-session-force": "${jboss.modcluster.sticky-session-force:false}",
                                        "sticky-session-remove": "${jboss.modcluster.sticky-session-remove:false}",
                                        "proxy-list": "#{v_proxy_list}",
                                      }
                                    }
      elsif f_profile_version(p_one_profile_cfg) < 7.0
        v_proxy_list = f_profile_cluster_address(p_one_profile_cfg).map { |one_address| "#{one_address}:#{def_cluster_port}" }.join(',')
        v_desired_mod_cluster_cfg = {
                                      "configuration": {
                                        "connector": "ajp",
                                        "advertise": "false",
                                        "balancer": '${jboss.modcluster.balancer:' + v_default_balancer_name + '}',
                                        "load-balancing-group": '${jboss.modcluster.load-balancing-group:' + v_default_lb_group_name + '}',
                                        "excluded-contexts": "${jboss.modcluster.excluded-contexts:ROOT,invoker,jbossws,juddi,console}",
                                        "worker-timeout": "${jboss.modcluster.worker-timeout:-1}",
                                        "stop-context-timeout": "${jboss.modcluster.stop-context-timeout:10}",
                                        "node-timeout": "${jboss.modcluster.node-timeout:-1}",
                                        "socket-timeout":  "${jboss.modcluster.socket-timeout:20}",
                                        "ping": "${jboss.modcluster.ping:10}",
                                        "flush-wait": "${jboss.modcluster.flush-wait:-1}",
                                        "smax": "${jboss.modcluster.smax:-1}",
                                        "ttl": "${jboss.modcluster.ttl:-1}",
                                        "flush-packets": "${jboss.modcluster.flush-packets:false}",
                                        "auto-enable-contexts": "${jboss.modcluster.auto-enable-contexts:true}",
                                        "max-attempts": "${jboss.modcluster.max-attempts:1}",
                                        "sticky-session": "${jboss.modcluster.sticky-session:true}",
                                        "sticky-session-force": "${jboss.modcluster.sticky-session-force:false}",
                                        "sticky-session-remove": "${jboss.modcluster.sticky-session-remove:false}",
                                        "session-draining-strategy": "${jboss.modcluster.session-draining-strategy:DEFAULT}",
                                        "proxy-list": "#{v_proxy_list}",
                                      }
                                    }
      else
        v_cluster_name_list = f_desired_outbound_state(p_profile_name, p_one_profile_cfg).keys
        v_desired_mod_cluster_cfg = {
                                      "default": {
                                        "connector": "ajp",
                                        "advertise": "false",
                                        "balancer": '${jboss.modcluster.balancer:' + v_default_balancer_name + '}',
                                        "load-balancing-group": '${jboss.modcluster.load-balancing-group:' + v_default_lb_group_name + '}',
                                        "excluded-contexts": "${jboss.modcluster.excluded-contexts:wildfly-services}",
                                        "worker-timeout": "${jboss.modcluster.worker-timeout:-1}",
                                        "stop-context-timeout": "${jboss.modcluster.stop-context-timeout:10}",
                                        "node-timeout": "${jboss.modcluster.node-timeout:-1}",
                                        "socket-timeout":  "${jboss.modcluster.socket-timeout:20}",
                                        "ping": "${jboss.modcluster.ping:10}",
                                        "flush-wait": "${jboss.modcluster.flush-wait:-1}",
                                        "smax": "${jboss.modcluster.smax:-1}",
                                        "ttl": "${jboss.modcluster.ttl:-1}",
                                        "flush-packets": "${jboss.modcluster.flush-packets:false}",
                                        "auto-enable-contexts": "${jboss.modcluster.auto-enable-contexts:true}",
                                        "max-attempts": "${jboss.modcluster.max-attempts:1}",
                                        "sticky-session": "${jboss.modcluster.sticky-session:true}",
                                        "sticky-session-force": "${jboss.modcluster.sticky-session-force:false}",
                                        "sticky-session-remove": "${jboss.modcluster.sticky-session-remove:false}",
                                        "session-draining-strategy": "${jboss.modcluster.session-draining-strategy:DEFAULT}",
                                        "proxies": v_cluster_name_list,
                                      }
                                    }
      end

      v_desired_mod_cluster_cfg
    end

    def f_srv_grp_jvm_options(p_one_srv_grp_name,p_one_srv_grp_cfg)
      init_mem_cfg_name = "-Xss"
      init_mem_cfg = "#{init_mem_cfg_name}256K"
      init_jvm_options = [\
                      "-Dorg.jboss.resolver.warning=true",\
                      "-Dsun.rmi.dgc.server.gcInterval=3600000",\
                      "-Dsun.lang.ClassLoader.allowArraySyntax=true",\
                      "-Dfile.encoding=utf-8",\
                      "-Duser.language=pt",\
                      "-Duser.region=BR",\
                      "-Duser.country=BR",\
                      "-Djava.awt.headless=true",\
                      "#{init_mem_cfg}",\
                      "-Djava.security.egd=file:/dev/./urandom"\
                    ]
      if f_enable_srv_group_gclog(p_one_srv_grp_cfg)
        init_jvm_options = init_jvm_options + [\
                                                "-verbose:gc",\
                                                "-Xloggc:#{f_gc_log_dir()}/#{p_one_srv_grp_name}.log",\
                                                "-XX:+PrintGCDetails",\
                                                "-XX:+PrintGCDateStamps",\
                                                "-XX:+PrintGCApplicationStoppedTime",\
                                              ]
      end
    
    v_jvm_options = p_one_srv_grp_cfg.fetch('jvm-options',[])
    v_desired_jvm_options = []
    
    if !v_jvm_options.nil? && !v_jvm_options.empty?
      v_jvm_options.each do |one_option|
        option_name = one_option.split('=')[0]
        name_end_pos = option_name.length
        selected_option = init_jvm_options.select {|item| item.eql?(option_name) || item[0..name_end_pos].eql?("#{option_name}=") }
        if selected_option.one?
          init_jvm_options.delete(selected_option[0])
        elsif option_name[0..3].eql?(init_mem_cfg_name) 
          init_jvm_options.delete(init_mem_cfg)
        end

        v_desired_jvm_options = v_desired_jvm_options << one_option
        
      end
      v_desired_jvm_options = v_desired_jvm_options.uniq + init_jvm_options
    else
      v_desired_jvm_options = init_jvm_options
    end
    if f_enable_srv_group_debug(p_one_srv_grp_cfg)
      v_desired_jvm_options = v_desired_jvm_options << "-agentlib:jdwp=transport=dt_socket,address=#{f_srv_group_debug_port(p_one_srv_grp_cfg)},server=y,suspend=n"
    end
    v_desired_jvm_options        
  end

  def f_base_debug_port
    f_domain_cfg.fetch('debug-base-port', 8087).to_i
  end

  def f_enable_srv_group_gclog(p_one_srv_grp_cfg)
    f_domain_cfg().fetch('enable-gclog', false) || p_one_srv_grp_cfg.fetch('enable-gclog', false)
  end

  def f_srv_group_debug_port(p_one_srv_grp_cfg)
    f_base_debug_port() + f_srv_port_offset(p_one_srv_grp_cfg).to_i
  end

  def f_srv_port_offset(p_one_srv_grp_cfg)
    p_one_srv_grp_cfg.fetch('socket-binding-port-offset', 0)
  end

  def f_enable_srv_group_debug(p_one_srv_grp_cfg)
    f_domain_cfg().fetch('enable-debug', false) || p_one_srv_grp_cfg.fetch('enable-debug', false)
  end

  def f_desired_jvm(p_one_srv_grp_name, p_one_srv_grp_cfg)
    v_jvm_desired_state = {}
    v_jvm_desired_state[p_one_srv_grp_name] = p_one_srv_grp_cfg.reject{ |k,v| !['heap-size', 'max-heap-size', 'permgen-size', 'max-permgen-size'].include? k }
    v_jvm_desired_state[p_one_srv_grp_name]['jvm-options'] = f_srv_grp_jvm_options(p_one_srv_grp_name,p_one_srv_grp_cfg)

    v_jvm_desired_state
  end
=begin
    def f_profile_version(p_one_profile_cfg)
      p_one_profile_cfg.fetch('version', f_domain_version())
    end
=end

    def f_profile_datasources(p_one_profile_cfg)
      p_one_profile_cfg.fetch('data-sources', {})
    end

    def f_setup_vault_ds_passwords(p_ds_cfg)
      p_ds_cfg.each_pair do |key, value|
        f_vault_add_item(key, 'password', f_ds_password(key, p_ds_cfg[key]))
      end
    end

    def f_desired_state_datasource(p_ds_cfg, p_txt_secdomain_name_prefix = '')
      if p_txt_secdomain_name_prefix.nil? || p_txt_secdomain_name_prefix.empty?
        v_ds_cfg = f_remove_keys(p_ds_cfg,  ['password', 'security-domain-username', 'security-domain-password'])
        p_ds_cfg.each_pair do |key, value|
          v_ds_cfg[key] = v_ds_cfg[key].merge({"password": "${#{f_vault_add_item(key, 'password', f_ds_password(key, p_ds_cfg[key]))}}"})
        end
      else
        v_ds_cfg = f_remove_keys(p_ds_cfg, ['password', 'user-name', 'security-domain-username', 'security-domain-password'])
        p_ds_cfg.each_pair do |key, value|
          v_ds_cfg[key] = v_ds_cfg[key].merge({"security-domain": "#{p_txt_secdomain_name_prefix}#{key}"})
        end
      end
      
      v_ds_cfg
    end

    def f_desired_state_xa_datasource(p_xa_ds_cfg, p_txt_secdomain_name_prefix = '')
      if p_txt_secdomain_name_prefix.nil? || p_txt_secdomain_name_prefix.empty?
        v_xa_ds_cfg = f_remove_keys(p_xa_ds_cfg,  ['password', 'security-domain-username', 'security-domain-password', 'xa-datasource-properties'])
        p_xa_ds_cfg.each_pair do |key, value|
          v_xa_ds_cfg[key] = v_xa_ds_cfg[key].merge({"password": "${#{f_vault_add_item(key, 'password', f_ds_password(key, p_xa_ds_cfg[key]))}}"})
        end
      else
        v_xa_ds_cfg = f_remove_keys(p_xa_ds_cfg, ['password', 'user-name', 'security-domain-username', 'security-domain-password', 'xa-datasource-properties'])
        p_xa_ds_cfg.each_pair do |key, value|
          v_xa_ds_cfg[key] = v_xa_ds_cfg[key].merge({"security-domain": "#{p_txt_secdomain_name_prefix}#{key}"})
        end
      end
      
      v_xa_ds_cfg
    end

    def f_profile_xa_datasources(p_one_profile_cfg)
      p_one_profile_cfg.fetch('xa-data-sources', {})
    end

    def f_profile_sec_domains(p_one_profile_cfg)
      p_one_profile_cfg.fetch('security-domains', {})
    end

    def f_sec_domain_options(p_one_sec_domain_cfg)
      p_one_sec_domain_cfg.fetch('module-options', {})
    end

    def f_sec_domain_code(p_one_sec_domain_cfg)
      p_one_sec_domain_cfg.fetch('code')
    end

    def f_sec_domain_flag(p_one_sec_domain_cfg)
      p_one_sec_domain_cfg.fetch('flag', 'required')
    end

    def f_encrypt_password(p_txt, p_jboss_mod_dir)
      v_picketbox_path = "#{p_jboss_mod_dir}/system/layers/base/org/picketbox/main/picketbox.jar"
      v_cmd = "java -classpath #{v_picketbox_path} org.picketbox.datasource.security.SecureIdentityLoginModule '#{p_txt}' | cut -d\: -f2"
      response(v_cmd).strip
    end

    def f_ds_item_value(p_ds_name, p_one_ds_cfg, p_item_key)
      v_item_value = f_generic_dbitem_get_value(p_ds_name, p_item_key, '', false)
      if v_item_value.empty?
        v_item_value = p_one_ds_cfg[p_item_key]
      end

      v_item_value
    end

    def f_ds_username(p_ds_name, p_one_ds_cfg)
      f_ds_item_value(p_ds_name, p_one_ds_cfg, 'user-name')
    end

    def f_ds_password(p_ds_name, p_one_ds_cfg)
      f_ds_item_value(p_ds_name, p_one_ds_cfg, 'password')
    end

    #Será removido, ver f_profile_log_handler
    def f_profile_syslog_handler(p_profile_name, p_one_profile_cfg)
    
     default_syslog_handler =  if f_is_remote_log() 
                                  {
                                    'auto_remote_log': {
                                      'app-name': "app_jboss_#{p_profile_name}",
                                      'facility': 'local-use-4',
                                      'server-address': f_logserver_addr(),
                                      'port': f_logserver_port(),
                                      'level': 'INFO',
                                      'hostname': '${jboss.host.name}-${jboss.server.name}',
                                    }                             
                                  }
                              else
                               {}
                              end

      p_one_profile_cfg.fetch('syslog-handlers', default_syslog_handler)
    end

    def f_profile_log_handler(p_profile_name, p_one_profile_cfg)
     default_custom_handler =  if f_is_remote_log() 
                                  {
                                    'custom-handler' => {
                                      'auto_remote_log' => {
                                        'class' => 'org.jboss.logmanager.handlers.SyslogHandler',
                                        'module' => 'org.jboss.logmanager',
                                        'formatter' => '"%d{HH:mm:ss,SSS} %-5p [%c] (%t) %s%E"',
                                        'level' => 'INFO',
                                        'properties' => {
                                          'serverHostname' =>  f_logserver_addr(),
                                          'port' => f_logserver_port(),
                                          'hostname' => '${jboss.host.name}-${jboss.server.name}',
                                          'appName' => "app_jboss_#{p_profile_name}",
                                          'facility' => 'LOCAL_USE_4',
                                          'syslogType' => 'RFC5424'
                                        }                                      
                                      }
                                    }
                                  }
                              else
                               {}
                              end

      p_one_profile_cfg.fetch('log-handler', default_custom_handler)
    end

    def f_my_tx_id_suffix
      "-Tx#{format('%03d', f_my_host_id())}"
    end

    def f_my_server_id_suffix
      "-server#{format('%03d', f_my_host_id())}"
    end

    def f_expand_role_map(p_role_mapping)
      p_role_mapping.map { |k,v| v.is_a?(Hash) ? [k, v] : [k, { "groups" => v } ] }.to_h
    end

    def f_jboss_user_roles
      f_default_role_map.keys
    end

    def f_default_role_map
      f_expand_role_map({
        "Administrator" => [],
        "Auditor" => [],
        "Deployer" => [],
        "Maintainer" => [],
        "Monitor" => {
          "groups" => [],
          "users" => ["#{f_ldap_principal_acc()}"]
        },
        "Operator" => [],
        "SuperUser" => []
      })
    end

    def f_jboss_ldap_role_mappings
      c_mandatory_monitor_user = { "Monitor" => { "users" => ["#{f_ldap_principal_acc()}"] }}

      v_role_mapping = f_domain_cfg().fetch('ldap-role-mapping', {})

      v_role_mapping = v_role_mapping.nil? ? f_default_role_map() : f_default_role_map().merge(f_expand_role_map(v_role_mapping))

      v_role_mapping.merge(c_mandatory_monitor_user){|key, oldval, newval| newval.merge(oldval){ |key2, oldval2, newval2| (oldval2+newval2).uniq }}
    end

    def f_ldap_server_address
      ldap_server_url = f_ldap_server_url()
      ldap_server_url[(ldap_server_url.rindex(/\//)) + 1 .. ldap_server_url.length].strip
    end

    def f_ldap_cert_path
      "#{f_sys_ca_cert_dir()}/#{f_ldap_server_address()}.crt"
    end

    def f_ldap_truststore_path
      "#{f_truststore_dir()}/ldap-truststore.jks"
    end

    def f_https_truststore_path
       "#{f_truststore_dir()}/httpsmgmtkeystore.jks"
    end

    def f_vault_add_item(p_block_name, p_attr_name, p_attr_value)
      f_execute_vault(p_block_name, p_attr_name, p_attr_value, false)
    end

    def f_init_vault_reqs
      vault_secret = f_vault_secret()
      vault_salt = f_vault_salt()
      vault_path = f_vault_path()
      vault_dir = f_vault_dir()
      vault_alias = f_vault_alias()
      vault_iter_count = f_vault_iter_count()

      keytool_cmd = "sudo -u jboss /usr/bin/keytool -genseckey -alias #{vault_alias} -storetype jceks -keyalg AES -keysize 128 -storepass #{vault_secret}"
      keytool_cmd = " #{keytool_cmd} -keypass #{vault_secret} -validity 7300 -keystore #{vault_path}"
      execute 'create keystore to vault' do
        command keytool_cmd
        action :run
        not_if { ::File.exist? vault_path }
        sensitive true
      end
    end

    def f_init_vault
      f_execute_vault('vaultinit', 'password', f_vault_initpass(), true)
    end

    def f_execute_vault(p_block_name, p_attr_name, p_attr_value, p_init)
      vault_cmd = "sudo -u jboss #{f_my_version() < 6.4 ? 'JAVA_OPTS="-Djboss.modules.system.pkgs=com.sun.crypto.provider" ' : ''}#{f_eap_dir()}/bin/vault.sh"
      vault_cmd = "#{vault_cmd} --keystore #{f_vault_path()} --keystore-password '#{f_vault_secret()}' --alias #{f_vault_alias()}"
      vault_cmd = "#{vault_cmd} --vault-block #{p_block_name} --attribute #{p_attr_name} --sec-attr '#{p_attr_value}'"
      vault_cmd = "#{vault_cmd} --enc-dir #{f_vault_dir()} --iteration #{f_vault_iter_count()} --salt '#{f_vault_salt()}'"
      if f_my_mj_version() > 6
        vault_cmd = "#{vault_cmd} 2>&1 1>/dev/stdout  | sed -e '/\\/host=.*$\\|VAULT.*/ ! s/.*//g' | grep #{p_init ? 'host\=' : 'VAULT'}"
      else
        vault_cmd = "#{vault_cmd} 2>&1 1>/dev/stdout  | sed -e '/<vault.*\\|VAULT.*/ ! s/.*//g' | grep #{p_init ? '\<vault' : 'VAULT'}"
      end

      vault_cfg = response(vault_cmd)

      if vault_cfg.nil? || vault_cfg.strip.empty?
        raise "error during vault operation: block => #{p_block_name}, attribute => #{p_attr_name}, cmd => #{vault_cmd}"
      elsif !p_init
        vault_cfg = vault_cfg.strip 
      elsif f_my_mj_version() > 6
        vault_cfg = vault_cfg.strip.sub('the_host', node['hostname'])
      else
        vault_cfg = "#{vault_cfg}</vault>"
      end

      vault_cfg      
    end

    def f_init_ssl_cert_legacy64
      var_cmd = "sudo -u jboss /usr/bin/keytool -genkeypair -alias #{node['hostname']} -storetype jks -keyalg RSA -keysize 2048 -keypass '#{f_truststore_secret()}'"
      var_cmd = "#{var_cmd} -keystore #{f_https_truststore_path()} -storepass '#{f_truststore_secret()}'"
      var_cmd = "#{var_cmd} -dname \"CN=#{node['fqdn']},OU=STI,O=TRF2,L=Rio de Janeiro,ST=RJ,C=BR\" -validity 7300 -v"

      execute 'generate key pair https console' do
        command var_cmd
        action :run
        not_if "test -f #{f_https_truststore_path()}"
      end

      var_export = "/usr/bin/keytool -exportcert -alias #{node['hostname']} -rfc -file #{f_my_cert_path()}"
      var_export = "#{var_export} -keystore #{f_https_truststore_path()} -storepass '#{f_truststore_secret()}'"

      execute "exrpotr my certificate #{f_my_cert_path()}" do
        command var_export
        action :run
      end

    end

    def f_my_jgroups_hosts
      jgroups_members = []

      f_my_server_groups().each_pair do |_prf_name, srv_groups|
        sys_props = srv_groups.map { |_grp_name, grp_cfg| f_system_properties(grp_cfg) }[0]
        if sys_props.key?('jboss.cluster.tcp.initial_hosts')
          init_hosts_txt = sys_props.fetch('jboss.cluster.tcp.initial_hosts')['value'].strip
          jgroups_members = jgroups_members + init_hosts_txt.gsub('[','/32:')[0..-2].split('],')
        end
      end

      log jgroups_members.to_s

      jgroups_members
    end
  end
end