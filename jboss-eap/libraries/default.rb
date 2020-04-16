module EAP
  JBOSS_DEFAULT_CONF = {
    rpm: {
      '7': {
        jboss_home: '/opt/rh/eap7/root/usr/share/wildfly',
        service_conf: '/etc/opt/rh/eap7/wildfly/eap7-domain.conf',
        started_code: 'WFLYSRV0025'
      },
      '6': {
        jboss_home: '/usr/share/jbossas',
        service_conf: '/etc/jbossas/jbossas.conf',
        started_code: 'JBAS015874'
      }
    },
    zip: {
      '6': {
        jboss_home: '',
        service_conf: 'bin/init.d/jboss-as.conf',
        link_service_conf: '/etc/jboss-as/jboss-as.conf',
        init_script: 'bin/init.d/jboss-as-domain.sh',
        started_code: 'JBAS015874'
      },
      '7': {
        jboss_home: '',
        service_conf: 'bin/init.d/jboss-eap.conf',
        link_service_conf: '/etc/default/jboss-eap.conf',
        init_script: 'bin/init.d/jboss-eap-rhel.sh',
        started_code: 'WFLYSRV0025'
      }
    }
  }
  JBOSS_USER = 'jboss'
  JBOSS_GROUP = 'jboss'
  LINK_HOME =  '/opt/jboss'
  SUB_HOME = '/opt'
  LINK_CONFIG = '/opt/jboss/service-config'
  LOG_BASE_DIR = '/var/log/jboss'
  SYS_CERT_PATH = '/etc/ssl/certs'
  SYS_CA_CERT_PATH = '/etc/pki/ca-trust/source/anchors'
  YUM_GROUP_BNAME = 'jboss-eap'
  TRUSTSTORE_DEF_SBDIR = 'certificados'
  CREDSTORE_DEF_SBDIR = 'credenciais'
  JB_DATABAG = 'dtbg_jboss_conf'
  JB_DATABAG_TRUST = 'trust_conf'
  JB_DATABAG_JBOSSCLI = 'jbosscli_conf'
  JB_DATABAG_SLAVE = 'slave_conf'
  JB_DATABAG_LDAP = 'ldap_conf'
  LDAP_CREDSTR_NAME = 'ldap_cred_str'
  MASTER_SSL_KEYSTORE = 'httpsKS'
  PVT_JGROUPS_NETWORK = '192.168.72.'
  DEFAULT_MAJOR_VERSION = 7
  DEFAULT_RELEASE = 2
  DEFAULT_SRC_PROFILE = 'ha'
  DEFAULT_UNDERTOW_BUFFER_SIZE = '1048576‬'
  DEFAULT_CLUSTER_PORT = 6666
  DEFAULT_CONSOLE_PORT = [9993, 9990]
  DEFAULT_UTIL_SOFT_BDIR = '/util'
  DEFAULT_UTIL_SOFT_CFG = {
                            :basedir => '/util',
                            :soft => {
                              :josie => {
                                :'git-repo' => "josie.git",
                                :'git-enable-submodule' => true,
                                :command => ["josie.py"],
                                :'package-req' => ["python-requests", "python-urllib3"],
                                :'add-path' => ["/tmp/deploy-script"]
                              },
                              :'jbosscli-converge' => {
                                :'git-repo' => "jbosscli-converge.git",
                                :'git-enable-submodule' => true,
                                :command => ["converge.py"],
                                :'req-package' => ["python-requests", "python-urllib3"]
                              }
                            }
                          }
end

