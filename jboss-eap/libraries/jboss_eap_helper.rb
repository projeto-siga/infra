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
  module Helper
    def response(p_cmd)
      v_output = begin
                  Chef::Resource::RubyBlock.send(:include, Chef::Mixin::ShellOut)
                  resp = shell_out(p_cmd)
                  resp.stdout
                 rescue
                  ''
                 end

      v_output
    end

    def f_base_url(p_url)
      p_url[0..(p_url.rindex('/'))]
    end

    def f_domain_cfg
      node.fetch('jboss')
    end

    def f_force_reinstall
      f_domain_cfg().fetch('reinstall', false)
    end

    def f_modules_cfg
      f_domain_cfg().fetch('modules', {})
    end

    def f_master_ipaddress
      f_domain_cfg().fetch('master-address')
    end

    def f_master_fqdn
       f_domain_cfg().fetch('master-fqdn', response("dig +short -x #{f_master_ipaddress()}").strip[0..-2])
    end

    def f_domain_name
      f_domain_cfg().fetch('domain-name', f_master_fqdn().split('.').first + ' domain')
    end

    def am_i_master
      node['ipaddress'].eql? f_master_ipaddress()
    end

    def f_eap_dir
      f_domain_cfg().fetch('eap-dir', EAP::LINK_HOME)
    end

    def f_sys_cert_dir
      EAP::SYS_CERT_PATH
    end

    def f_sys_ca_cert_dir
      EAP::SYS_CA_CERT_PATH
    end

    def f_my_cert_path
      "#{f_sys_cert_dir()}/#{node['fqdn']}.crt"
    end

    def f_master_ssl_keystore
      EAP::MASTER_SSL_KEYSTORE
    end

    def f_config_dir
      "#{f_domain_dir()}/configuration"
    end

    def f_default_conf(p_major_version)
      f_is_rpm_install() ? EAP::JBOSS_DEFAULT_CONF.fetch(:rpm).fetch(p_major_version.to_s.to_sym) : EAP::JBOSS_DEFAULT_CONF.fetch(:zip).fetch(p_major_version.to_s.to_sym)
    end

    def f_install_service_conf_path(p_major_version=f_my_mj_version())
      v_service_conf_path = f_default_conf(p_major_version).fetch(:service_conf)

      f_is_rpm_install() ? v_service_conf_path : "#{f_install_home_dir()}/#{v_service_conf_path}"
    end

    def f_install_service_conf_ln_path(p_major_version=f_my_mj_version())
      v_service_conf_ln_path = f_default_conf(p_major_version).fetch(:link_service_conf, '')

      v_service_conf_ln_path
    end

    def f_service_conf_link(p_major_version)

    end

    def f_is_rpm_install
      v_is_rpm = if am_i_master() || !am_i_legacy()
                  f_domain_mj_version() >= 7 ? f_domain_cfg().fetch('is-rpm', true) : f_domain_cfg().fetch('is-rpm', false)
                else
                  f_my_mj_version() >= 7 ? f_legacy_slaves().fetch('is-rpm', true) : f_legacy_slaves().fetch('is-rpm', false)
                end
      v_is_rpm
    end

    def f_eap_zip_url
      v_eap_zip_url = if  f_is_rpm_install()
                        ''
                      elsif am_i_master() || !am_i_legacy()
                        f_domain_mj_version() >= 7 ? f_domain_cfg().fetch('eap-zip-url') : f_domain_cfg().fetch('eap-zip-url')
                      else
                        f_legacy_slaves().fetch(node['hostname']).fetch('eap-zip-url')
                      end
      v_eap_zip_url
    end

    def f_dirname_on_zip(p_zip_file)
      v_dirname = response("unzip -l #{p_zip_file} | sed -e '4!d' -e 's/.* \\(.*\\/\\).*/\\1/g'").strip

      if v_dirname.empty?
        raise "erro em conteúdo #{p_zip_file}"
      end

      v_dirname.delete_suffix('/')
    end

    def f_jboss_user
      EAP::JBOSS_USER
    end

    def f_jboss_group
      EAP::JBOSS_GROUP
    end

    def f_install_home_subdir
      EAP::SUB_HOME
    end

    def f_install_home_dir(p_major_version=f_my_mj_version(), p_version=f_my_version())
      f_is_rpm_install() ? f_default_conf(p_major_version).fetch(:jboss_home) : "#{f_install_home_subdir()}/jboss-eap-#{p_version}"
    end

    def f_log_dir
      "#{f_domain_dir()}/log"
    end
    
    def f_sys_log_base_dir
      EAP::LOG_BASE_DIR
    end

    def f_domain_dir
      "#{f_eap_dir()}/domain"
    end

    def f_servers_dir
      "#{f_domain_dir()}/servers"
    end

    def f_server_log_dir(p_server_name)
      "#{f_servers_dir()}/#{p_server_name}/log"
    end

    def f_modules_dir
      "#{f_eap_dir()}/modules"
    end

    def f_credstore_dir
      "#{f_eap_dir()}/#{EAP::CREDSTORE_DEF_SBDIR}"
    end

    def f_truststore_dir
      "#{f_eap_dir()}/#{EAP::TRUSTSTORE_DEF_SBDIR}"
    end

    def f_domain_version
      f_domain_cfg.fetch('version', "#{EAP::DEFAULT_MAJOR_VERSION}.#{EAP::DEFAULT_RELEASE}").to_f
    end

    def f_domain_mj_version
      f_domain_version().floor
    end

    def f_legacy_slaves
      f_domain_cfg().fetch('legacy-slave-hosts', {})
    end

    def has_legacy_slaves
      f_legacy_slaves().any?
    end

    def f_non_legacy_slavenames
      f_domain_cfg().fetch('slave-hosts')
    end

    def f_legacy_slavenames
      f_legacy_slaves().keys
    end

    def f_all_slavenames
      f_non_legacy_slavenames() + f_legacy_slavenames()
    end

    def f_my_version
      f_version(node['hostname'])
    end

    def f_my_mj_version
       f_my_version().floor
    end

    def f_version(p_slavename)
      v_version = f_domain_version()
      if is_legacy_eap(p_slavename)
        v_version = f_legacy_slaves().fetch(p_slavename).fetch('version')
      end
      v_version
    end

    def f_my_service_name
      "eap#{f_my_mj_version()}-domain"
    end

    def f_yum_groupname
      "#{EAP::YUM_GROUP_BNAME}#{f_my_mj_version()}"
    end

    def f_ext_module_zip_url
       v_eap_zip_url = if am_i_master() || !am_i_legacy()
                        f_domain_cfg().fetch('ext-module-zip-url')
                      else
                        f_legacy_slaves().fetch(node['hostname']).fetch('ext-module-zip-url')
                      end
      v_eap_zip_url
    end

    def f_ext_module_pulp_manifest
      v_eap_manifest_url = if am_i_master() || !am_i_legacy()
                            f_domain_cfg().fetch('ext-module-pulp-mafifest-url')
                          else
                            f_legacy_slaves().fetch(node['hostname']).fetch('ext-module-pulp-mafifest-url')
                          end
      v_eap_manifest_url
    end

    def am_i_legacy
      f_legacy_slaves().keys.include?(node['hostname'])
    end

    def f_started_code
      f_default_conf(f_my_mj_version()).fetch(:started_code)
    end

    def f_config_file_name(p_is_domainfl, p_is_master, p_domain_name)
      v_config_filename = if p_is_domainfl
                            "domain-#{p_domain_name.gsub(/[^0-9a-z ]/i, '').tr(' ', '_')}.xml"
                          else
                            "host-#{p_is_master ? 'master' : 'slave'}-#{p_domain_name.gsub(/[^0-9a-z ]/i, '').tr(' ', '_')}.xml"
                          end
      v_config_filename
    end

    def f_util_soft_install_cfg
      f_domain_cfg().fetch('util-soft-install-cfg', EAP::DEFAULT_UTIL_SOFT_CFG)
    end

    def f_util_soft_base_dir(p_util_soft_repo_cfg)
      p_util_soft_repo_cfg.fetch(:'basedir', p_util_soft_repo_cfg.fetch('basedir', EAP::DEFAULT_UTIL_SOFT_BDIR))
    end

    def f_util_soft_cfg(p_util_soft_repo_cfg)
      p_util_soft_repo_cfg.fetch(:'soft', p_util_soft_repo_cfg.fetch('soft', {}))
    end

    def f_util_soft_req_packages(p_one_util_soft_cfg)
      p_one_util_soft_cfg.fetch(:'req-package', p_one_util_soft_cfg.fetch('req-package', []))
    end

    def f_util_soft_add_path(p_one_util_soft_cfg)
      p_one_util_soft_cfg.fetch(:'add-path', p_one_util_soft_cfg.fetch('add-path', []))
    end

    def f_util_soft_git_repo(p_one_util_soft_cfg)
       git_repo = p_one_util_soft_cfg.key?(:'git-repo') ? p_one_util_soft_cfg.fetch(:'git-repo') : p_one_util_soft_cfg.fetch('git-repo')
       git_repo.start_with?('http') ? git_repo : "#{f_default_git_base_url()}#{git_repo}"
    end

    def f_util_soft_git_ena_submodule(p_one_util_soft_cfg)
      p_one_util_soft_cfg.fetch(:'git-enable-submodule', p_one_util_soft_cfg.fetch('git-enable-submodule', false))
    end

    def f_util_soft_command_file(p_one_util_soft_cfg)
      p_one_util_soft_cfg.fetch(:'command',  p_one_util_soft_cfg.fetch('command', []))
    end

    def f_default_git_base_url
      base_url = f_domain_cfg().fetch('default-git-base-url')
      base_url[-1].eql?('/') ? base_url : "#{base_url}/"
    end

    def f_private_fulladdress
      node_networkif_cfg = node.fetch('network').fetch('interfaces').select { |k, _v| k != 'default_interface' && k != 'default_gateway' && k != 'lo' }

      pvt_interface_cfg = node_networkif_cfg.select { |_k, v| (v.fetch('addresses').keys.find { |v_ip| v_ip.match(EAP::PVT_JGROUPS_NETWORK) }).nil? ? false : true }

      pvt_if_addr_cfg = nil
      if !pvt_interface_cfg.nil? && pvt_interface_cfg.any?
        pvt_if_addr_cfg = pvt_interface_cfg.fetch(pvt_interface_cfg.keys.first).fetch('addresses').select { |k, _v| k.match(EAP::PVT_JGROUPS_NETWORK) }
      end
      pvt_if_ipaddr = (!pvt_if_addr_cfg.nil? && pvt_if_addr_cfg.any?) ? pvt_if_addr_cfg.keys.first : nil
      pvt_if_ip_prefixlen = pvt_if_ipaddr.nil? ? 0 : pvt_if_addr_cfg.fetch(pvt_if_ipaddr).fetch('prefixlen')

      pvt_if_ipaddr.nil? ? nil : "#{pvt_if_ipaddr}/#{pvt_if_ip_prefixlen}"
    end

    def f_private_ipaddress(pvt_if_fulladdr)
      pvt_if_fulladdr.split('/')[0]
    end

    def f_private_ip_prefixlen(pvt_if_fulladdr)
      pvt_if_fulladdr.split('/')[1]
    end

    def is_legacy_eap(p_slavename)
      f_legacy_slavenames().include?(p_slavename)
    end

    def has_legacy_slave
      f_legacy_slavenames().any?
    end

    def f_my_server_groups
      v_my_server_groups_cfg = {}
      v_my_profiles_cfg = f_my_profiles()
      v_my_profile_names = v_my_profiles_cfg.keys
      v_my_profile_names.each do |v_profile_name|
        srv_groups_hash = filter_my_srv_groups(f_profile_server_groups(v_my_profiles_cfg.fetch(v_profile_name)))
        v_my_server_groups_cfg = v_my_server_groups_cfg.merge({ "#{v_profile_name}": srv_groups_hash })
      end
      v_my_server_groups_cfg
    end

    def f_my_server_groupnames
      v_srv_grp_names = []
      f_my_server_groups().each_pair do |v_profile_name, v_one_prof_cfg|
        v_srv_grp_names = v_srv_grp_names + v_one_prof_cfg.keys
      end

      v_srv_grp_names
    end

    def f_profile_server_groups(p_profiles_cfg)
      p_profiles_cfg.fetch('server-groups')
    end

    def f_my_profiles
      v_my_profiles = if am_i_master()
                        f_profiles()
                      else
                        f_profiles().select { |_k, v| filter_my_srv_groups(f_profile_server_groups(v)).any? }
                      end
      v_my_profiles
    end

    def f_profiles
      f_domain_cfg().fetch('profiles')
    end

    def filter_my_srv_groups(p_srv_groups)
      p_srv_groups.select { |_k2, v_srv| f_slavenames_in_srvgroup(v_srv).include? node['hostname'] }
    end

    def f_slavenames_in_srvgroup(p_srv_group)
      p_srv_group.fetch('slave-hosts', f_non_legacy_slavenames())
    end

    def f_my_host_id
      v_host_id = if is_legacy_eap(node['hostname'])
                    f_legacy_slavenames().index(node['hostname']) + 901
                  else
                    f_non_legacy_slavenames().index(node['hostname']) + 1
                  end
      v_host_id
    end

    def f_system_properties(p_one_partent_cfg)
      v_raw_sys_prop = p_one_partent_cfg.fetch('system-properties', {})
      v_system_prop = v_raw_sys_prop.map { |k,v| v.is_a?(Hash) ? [k, v] : [k, {"value"=>v, "boot-time"=>false} ] }.to_h

      v_system_prop
    end

    def f_jboss_dbag_name
      EAP::JB_DATABAG
    end

    def f_generic_dbitem_get_value(p_dbitem_name, p_dbitem_idx, p_default_value, p_enforce)
      v_config_value = p_default_value
      v_dbitem_conf = begin
                      data_bag_item(f_jboss_dbag_name(), p_dbitem_name) 
                    rescue
                      if !p_enforce
                        nil
                      else
                        raise "A chave de config #{p_dbitem_idx} é necessária no encrypted dbitem #{p_dbitem_name}."
                      end
                    end
      if !v_dbitem_conf.nil?
        v_config_value = (v_dbitem_conf[p_dbitem_idx].nil? || v_dbitem_conf[p_dbitem_idx].empty?) ? v_config_value : v_dbitem_conf[p_dbitem_idx]
      end
      v_config_value
    end

    def f_default_slave_prefix_pass
      f_generic_dbitem_get_value(EAP::JB_DATABAG_SLAVE, 'secret', 'MeuPr3fixoTeste', false)
    end

    def f_slave_secret(p_slavename=node['hostname'])
      v_slave_secret = "#{f_default_slave_prefix_pass()}@#{p_slavename}"

      if p_slavename.nil? || p_slavename.empty?
        v_slave_secret = "#{f_default_slave_prefix_pass()}#{v_slave_secret}"
      end

      v_slave_secret
    end

    def f_slave_secret_b64(p_slavename=node['hostname'])
      Base64.encode64(f_slave_secret(p_slavename)).strip!
    end

    def f_truststore_secret
      f_generic_dbitem_get_value(EAP::JB_DATABAG_TRUST, 'secret', 'iTmUsTb3CH4nged', false)
    end

    def f_jbosscli_secret
      f_generic_dbitem_get_value(EAP::JB_DATABAG_JBOSSCLI, 'secret', 'iTmUsTb3CH4nged', false)
    end

    def f_ldap_credstore_name()
      EAP::LDAP_CREDSTR_NAME
    end

    def f_ldap_server_url
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'url', '', true)
    end

    def f_ldap_credstore_pw
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'credential-store-pw', '', true)
    end

    def f_ldap_filter_base_dn
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'filter-base-dn', '', true)
    end

    def f_ldap_search_base_dn
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'search-base-dn', '', true)
    end

    def f_ldap_principal
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'principal', '', true)
    end

    def f_ldap_principal_acc
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'pincipal-acc', '', true)
    end

    def f_ldap_principal_pw
      f_generic_dbitem_get_value(EAP::JB_DATABAG_LDAP, 'principal-pw', '', true)
    end

    def f_profile_undertow_buffer_size(p_one_profile_cfg)
      p_one_profile_cfg.fetch('undertow-buffer-size', EAP::DEFAULT_UNDERTOW_BUFFER_SIZE).to_i
    end

    def f_profile_webservice_fqdn(p_one_profile_cfg)
      p_one_profile_cfg.fetch('webservice-ext-fqdn')
    end

    def f_profile_cluster_address(p_one_profile_cfg)
      p_one_profile_cfg.fetch('cluster-address')
    end

    def f_my_cluster_addresses
      v_cluster_addresses = []

      f_my_profiles().each_pair do |profile_name, one_profile_cfg|
        v_cluster_addresses += one_profile_cfg.fetch('cluster-address')
      end

      v_cluster_addresses
    end

    def f_src_profile_name(p_one_profile_cfg)
      p_one_profile_cfg.fetch('src-profile-name', EAP::DEFAULT_SRC_PROFILE)
    end

    def f_profile_log_tag(p_profile_name, p_one_profile_cfg)
      p_one_profile_cfg.fetch('log-tag',"app#{p_profile_name}")
    end
    
    def f_enable_activemq(p_one_profile_cfg)
      v_enable_ativemq = if f_src_profile_name(p_one_profile_cfg) =~ /^full/
                          true
                         else
                          false
                         end
      v_enable_ativemq
    end

    def f_activemq_pass(p_one_profile_cfg)
      f_enable_activemq(p_one_profile_cfg) ? p_one_profile_cfg.fetch('activemq-pass') : p_one_profile_cfg.fetch('activemq-pass','')
    end

    def f_use_local_hibernate_cache(p_one_profile_cfg)
      p_one_profile_cfg.fetch('use-local-hibernate-cache', true)
    end

    def f_use_local_server_cache(p_one_profile_cfg)
      p_one_profile_cfg.fetch('use-local-server-cache', true)
    end

    def f_use_local_ejb_cache(p_one_profile_cfg)
      p_one_profile_cfg.fetch('use-local-ejb-cache', true)
    end

    def f_use_local_web_cache(p_one_profile_cfg)
      p_one_profile_cfg.fetch('use-local-web-cache', true)
    end

    def f_is_remote_log
      node.key?('log-client-config')
    end

    def f_logserver_conf
      f_is_remote_log() ? node.fetch('log-client-config') : {} 
    end

    def f_logserver_addr
      f_is_remote_log() ? f_logserver_conf().fetch('servername') : nil
    end

    def f_logserver_port
      v_port = if !f_is_remote_log() 
                    nil
                  else
                    f_logserver_conf().fetch('port', 20514)
                  end
      v_port
    end

    def f_logserver_protocol
      v_is_tcp = f_logserver_conf().fetch('isTCP', true)
      v_protocol = if !f_is_remote_log() 
                    nil
                  elsif v_is_tcp
                    'TCP'
                  else
                    'UDP'
                  end

      v_protocol
    end

    def f_default_master_console_port()
      f_lowest_slave_version() < 7 ? EAP::DEFAULT_CONSOLE_PORT + [9999] : EAP::DEFAULT_CONSOLE_PORT
    end

    def f_default_cluster_port()
      EAP::DEFAULT_CLUSTER_PORT
    end

    def f_remove_keys(p_hash, p_keys_to_remove)
      v_new_hash = {}

      p_hash.each_pair do |key, value|
        v_new_hash[key] = value.reject{ |k,v| p_keys_to_remove.include? k }
      end

      v_new_hash
    end
  end
end
