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
      
      if f_profile_version(p_one_profile_cfg) < 7.0
        v_proxy_list = f_profile_cluster_address(p_one_profile_cfg).map { |one_address| "#{one_address}:#{def_cluster_port}" }.join(',')
        v_desired_mod_cluster_cfg = {
          "configuration": {
            "connector": "ajp",
            "load-balancing-group": '${segsap.modcluster.lbgroup:' + p_profile_name +'Default}',
            "advertise": "false",
            "excluded-contexts": "ROOT, invoker,jbossws,juddi,console",
            "proxy-list": "#{v_proxy_list}",
          }
        }
      else
        v_cluster_name_list = f_desired_outbound_state(p_profile_name, p_one_profile_cfg).keys
        v_desired_mod_cluster_cfg = {
            "default": {
            "advertise": "false",
            "excluded-contexts": "wildfly-services",
            "connector": "ajp",
            "load-balancing-group": '${segsap.modcluster.lbgroup:' + p_profile_name +'Default}',
            "proxies": v_cluster_name_list,
            }
          }
      end

      v_desired_mod_cluster_cfg
    end

    def f_srv_grp_jvm_options(p_one_srv_grp_cfg)
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
    v_jvm_desired_state[p_one_srv_grp_name]['jvm-options'] = f_srv_grp_jvm_options(p_one_srv_grp_cfg)

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

      
    def f_desired_state_datasource(p_ds_cfg, p_txt_secdomain_name_prefix)
      v_ds_cfg = f_remove_keys(p_ds_cfg, ['password', 'user-name', 'security-domain-username', 'security-domain-password'])

      p_ds_cfg.each_pair do |key, value|
        v_ds_cfg[key] = v_ds_cfg[key].merge({"security-domain": "#{p_txt_secdomain_name_prefix}#{key}"})
      end
      
      v_ds_cfg
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
  end
end