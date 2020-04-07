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
  class GetCertficate < Chef::Resource
    resource_name :get_certificate

    property :name, String
    property :address, String #usado como alias na action from_cli_offline
    property :port, Integer
    property :cert_path, String, default: ''
    property :keystore, String, default: ''
    property :domain_config_file, String, default: ''
    property :host_config_file, String, default: ''
    property :ca_trust_update, [TrueClass, FalseClass], default: false
    property :update_control, [TrueClass, FalseClass], default: false
    property :was_updated_filename, String, default: '/tmp/updated-server-certificate'

    action :do do
      name = new_resource.name
      address = new_resource.address
      port = new_resource.port
      ca_trust_update = new_resource.ca_trust_update
      update_control = new_resource.update_control
      was_updated_filename = new_resource.was_updated_filename
      cert_path = new_resource.cert_path
      if cert_path.nil? || cert_path.empty?
        cert_path = ca_trust_update ? "#{f_sys_ca_cert_dir()}/#{address}.#{port}.crt" : "#{f_sys_cert_dir()}/#{address}.#{port}.crt"
      elsif ca_trust_update && !cert_path.match(f_sys_ca_cert_dir())
        log "Para usar ca-trust-update, coloque o certificado deve ser criado em #{f_sys_ca_cert_dir()}."
        cert_file = cert_path[(cert_path.rindex(/\//)) + 1 .. cert_path.length].strip
        cert_path = "#{f_sys_ca_cert_dir()}/#{cert_file}"
        raise "Corrija o cert_path para #{cert_path} "
      end
      tmp_cert_path = "/tmp/#{address}.#{port}.crt"

      file was_updated_filename do
        action :delete
      end

      execute "download server certificate from #{address}:#{port}" do
        command "echo -n | openssl s_client -connect #{address}:#{port} | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > #{tmp_cert_path}"
        action :run
      end

      if update_control
        file was_updated_filename do
          content cert_path
          owner 'root'
          group 'root'
          mode '0644'
          action :create
          not_if "echo $(diff #{tmp_cert_path} #{cert_path} 1>/dev/null 2>&1; echo $?) | grep -q 0"
        end
      end

      file cert_path do
        content lazy { IO.read(tmp_cert_path) }
        action :create
        owner 'root'
        group 'root'
        mode '0664'
        if ca_trust_update
        notifies :run, 'execute[update-ca-trust]', :immediate
        end
        not_if "echo $(diff #{tmp_cert_path} #{cert_path} 1>/dev/null 2>&1; echo $?) | grep -q 0"
      end


      execute 'update-ca-trust' do
        command 'update-ca-trust'
        action :nothing
      end

      file tmp_cert_path do
        action :delete
      end

      file was_updated_filename do
        action :delete
      end
    end

    action :from_cli_offline do
      name = new_resource.name
      address = new_resource.address
      port = new_resource.port
      ca_trust_update = new_resource.ca_trust_update
      update_control = new_resource.update_control
      was_updated_filename = new_resource.was_updated_filename
      keystore = new_resource.keystore
      cert_path = new_resource.cert_path
      host_config_file = new_resource.host_config_file
      domain_config_file = new_resource.domain_config_file

      if keystore.nil? || keystore.empty?
        raise 'é necessário indicar o keystore'
      end

      if cert_path.nil? || cert_path.empty?
        cert_path = ca_trust_update ? "#{f_sys_ca_cert_dir()}/#{address}.#{port}.crt" : "#{f_sys_cert_dir()}/#{address}.#{port}.crt"
      elsif ca_trust_update && !cert_path.match(f_sys_ca_cert_dir())
        log "Para usar ca-trust-update, coloque o certificado deve ser criado em #{f_sys_ca_cert_dir()}}."
        cert_file = cert_path[(cert_path.rindex(/\//)) + 1 .. cert_path.length].strip
        cert_path = "#{f_sys_cert_dir()}/#{cert_file}"
        raise "Corrija o cert_path para #{cert_path} "
      end
      tmp_cert_path = "/tmp/#{address}.#{port}.crt"

      my_cert_cmd = "/host=#{node['hostname']}/subsystem=elytron/key-store=#{keystore}:export-certificate(alias=#{address},path=#{tmp_cert_path},pem=true)"

      if update_control
        file was_updated_filename do
          action :delete
        end
      end

      exec_cli_resource 'Get My Certificate' do
        cli_commands my_cert_cmd
        live_stream true
        echo_command true
        host_config_file host_config_file
        domain_config_file domain_config_file
        run_offline true
        action :apply
      end

      if update_control
        file was_updated_filename do
          content cert_path
          owner 'root'
          group 'root'
          mode '0644'
          action :create
          not_if "echo $(diff #{tmp_cert_path} #{cert_path} 1>/dev/null 2>&1; echo $?) | grep -q 0"
        end
      end

      file cert_path do
        content lazy { IO.read(tmp_cert_path) }
        action :create
        owner 'root'
        group 'root'
        mode '0664'
        not_if "echo $(diff #{tmp_cert_path} #{cert_path} 1>/dev/null 2>&1; echo $?) | grep -q 0"
      end

      file tmp_cert_path do
        action :delete
      end
    end

    action_class do
      include InfraEAP::Helper
    end
  end
end
