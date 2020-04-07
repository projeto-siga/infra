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
  class ExecCliResource < Chef::Resource
    resource_name :exec_cli_resource
    property :name, String
    property :cli_commands, String, default: ''
    property :jboss_eap_dir, String, default: '/opt/jboss'
    property :port_offset, Integer, default: 0
    property :address, String, default: lazy { node['ipaddress'] }
    property :template, String
    property :template_variables, Hash
    property :sensitive, [TrueClass, FalseClass], default: false
    property :ignore_failure, [TrueClass, FalseClass], default: false
    property :live_stream, [TrueClass, FalseClass], default: false
    property :run_offline, [TrueClass, FalseClass], default: false
    property :offline_start, [TrueClass, FalseClass], default: true
    property :host_config_file, String, default: ''
    property :domain_config_file, String, default: ''
    property :echo_command, [TrueClass, FalseClass], default: false
    property :jboss_user, String, default: EAP::JBOSS_USER
    property :jboss_group, String, default: EAP::JBOSS_GROUP
    property :major_version, Integer, default: 7


    action :apply do
      name               = new_resource.name
      cli_commands       = new_resource.cli_commands
      jboss_eap_dir      = new_resource.jboss_eap_dir
      port_offset        = new_resource.port_offset
      address            = new_resource.address
      template           = new_resource.template
      template_variables = new_resource.template_variables
      sensitive          = new_resource.sensitive
      ignore_failure     = new_resource.ignore_failure
      run_offline        = new_resource.run_offline
      offline_start      = new_resource.offline_start
      host_config_file   = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file
      live_stream        = new_resource.live_stream
      jboss_user         = new_resource.jboss_user
      jboss_group        = new_resource.jboss_group
      echo_command       = new_resource.echo_command
      major_version      = new_resource.major_version

      if major_version < 7
        if echo_command
          log '--echo-command not supported, turning it off.'
          echo_command = false
        end

        if run_offline
          log 'embed-host-controller not supported, trying to run connected.'
          run_offline = false
        end

      end

      if cli_commands.empty?
       cli_commands = name
      end

      echo_command_arg = echo_command ? ' --echo-command' : ''

      if run_offline and !host_config_file.end_with?('.xml')
        raise "É necessário informar o arquivo de configuração do host-controller"
      end

      if run_offline && !domain_config_file.end_with?('.xml')
        raise "É necessário informar o arquivo de configuração do domain"
      end

      if template.nil?
        commands = run_offline ? "embed-host-controller --host-config=#{host_config_file} --domain-config=#{domain_config_file}, " : ''
        commands = "#{commands}#{cli_commands}#{run_offline ? ',  stop-embedded-host-controller' : ''}"
        execute 'exec commands with jboss-cli' do
          command "sudo -u jboss #{jboss_eap_dir}/bin/jboss-cli.sh#{(run_offline) ? '' : ' -c'} --commands='#{commands}'#{echo_command_arg}"
          sensitive sensitive
          live_stream live_stream
        end
      else
        cli_path = "/tmp/exec-cli-#{name.gsub(' ','_')}.cli"
        v_node = {node: node}
        template cli_path do
          source 'exec_cli_offline_wrapper.erb'
          owner jboss_user
          group jboss_group
          sensitive sensitive
          mode '0640'
          variables(
            exec_cli_v_template: template,
            exec_cli_v_offline: run_offline,
            exec_cli_v_offline_start: offline_start,
            exec_cli_v_hostfile: host_config_file,
            exec_cli_v_domainfile: domain_config_file,
            exec_cli_v_variables: v_node.merge(template_variables.nil? ? {} : template_variables) 
          )
        end

        execute "apply  #{name}" do
          command "sudo -u jboss #{jboss_eap_dir}/bin/jboss-cli.sh#{(run_offline) ? '' : ' -c'} --file=#{cli_path}#{echo_command_arg}"
          sensitive sensitive
          ignore_failure ignore_failure
        end

        if sensitive
          execute "rm -f #{cli_path}"
        end
      end
    end
  end
end
