# jboss-eap Cookbook

Instala o jboss-eap e configura domain controllers e hosts baseado nas descrições presentes nos atributos, explicados mais adiante.

A Instalação cobre:
  * O JBoss-eap
    - Inclui drivers jdbc para sqlserver e oracle como módulos
  * Suporta diversas configurações separadas (profiles) para rodar mais de um sistema num mesmo host, por exemplo, sigadoc e sigarh
  * Configuração de:
    - system properties
    - server-groups e suas respectivas jvm's
    - Datasources com ou sem Legacy SecurityDomains
    - Legacy SecurityDomains
    - Integração com mod_cluster
    - Integralção com ldap no console web
    - Instalação como serviço
    - Comandos 'nativos' para iniciar e parar.
  * Integração com o [josie](https://github.com/raphaelpaiva/josie) (a automatização do deploy)
  * Liberação das portas no firewalld

### Host Controller
Podem existir apenas uma instância de host controller na mesma máquina. Ele terá perfil de master (domain controller) ou slave (conforme a configuração do domain)


### Domain
A configuração do domínio EAP

## Requisitos

### Plataformas

- Centos 7 ou RHEL 7. Na prática, qualquer distro que suporte o yum, systemd e firewalld.

- A receita confia que alguns pacotes estejam instalados, como por exemplo o `git`.

### Chef

- Chef 14.12 ou maior

### Cookbooks

- `keytool` - jboss-eap precisa do cookbook keytool para fazer as configurações de keystores. A instalação é automática.

### Databags

É requerida a criação do encrypted databg `dtbg_jboss_conf` com os seguintes itens:
- `ldap_conf`: Hash. Obrigatório. Guarda a configuração de bind ao LDAP para setup da autenticação LDAP no console do JBoss EAP 7.2
  - `credential-store-pw`: String. Obrigatório. Senha da credential store que será criada para guarda da senha ldap.
  - `filter-base-dn`: String. Obrigatório. Exemplo: "CN=Users,DC=Example,DC=Com"
  - `pincipal-acc`: String. Nome da conta de rede para bind. Exemplo: "jbind_user" (o nome do atributo ficou errado mesmo. é pincipal-acc)
  - `principal`: String. Obrigatório. DN da conta. Exemplo: "CN=jbind_user,CN=Users,DC=Example,DC=Com"
  - `principal-pw`: String. Obrigatório. Senha da conta.
  - `search-base-dn`: String. Obrigatório. Exemplo: "CN=Users,DC=Example,DC=Com"
- `slave_conf`: Hash. Opcional. No momento, possui apenas o atributo `secret` para guarda a string que será usada para criação da senha do slave junto ao DC.
- `trust_conf`: Hash. Opcional. No momento, possui apenas o atributo `secret` para guarda a string que será para proteção de keystore/truststore.
- `jbosscli_conf`: Hash. Opcional. No momento, possui apenas o atributo `secret` para guarda a string que será para proteção de keystore/truststore do jboss-cli.



Como criar databag?
```text
1- set editor=notepad
2- knife data bag create dtbg_jboss_conf ldap_conf --secret-file=arquivo_com_uma_chave_de_sua_escolha
3- Completar o json com os atributos necessários
4- sair do notepad
```

### LDAPS
- usuários: O indicado por `principal` e os usuários `jboss_suser` (role Superuser) e `jboss_bind` (role Monitor)
- grupos: jboss_administrator, jboss_monitor e jboss_deployer

### Custom "infra team" system-properties
- `segsap.modcluster.lbgroup`: Opcional. Default: `<profile_name>Default`. Configura atributo "load-balancing-group" do proxy default do modcluster. Interessante para uso em ambientes com mais de 1 server-group por aplicação, assim pode-se fazer (em alguns cenários) atualização da aplicação sem perda de sessão (sticky-session, suspend, deploy, resume...).


## Attributes

Este cookbook confia nos atributos especificados, divididos em categorias: _globais_ e do _domínio_.

Alguns atributos só fazem sentido para domain controllers; outros, para hosts slaves. Porém **eles especificam a configuração do domínio**. Ou seja, a ideia é construir uma configuração única por domínio através de roles e a receita os usará conforme o papel do servidor (identificado também por atributos).

### Atributos globais

São os atributos que se aplicam ao host como um todo, não apenas à uma instância. Um exemplo útil é a configuração dos módulos a serem instalados:

Ou o mapeamento de deployments para server-groups (utilizado pela josie):


Exemplo:
```json
"server-group-mapping": {
  "example.war": "example",
  "siga.war": "siga",
  "sigadoc.war": "siga"
}
```

### Atributos do domínio

Configura-se o domínio com um Hash chamada `jboss`.
- `default-git-base-url`: String. Opcional. URL usada como base para as ferramentas adicionais padrão que a receita utiliza (jboss-cli e josie).
- `ext-module-zip-url`: String. Opcional. URL usada para download de descompactação de módulos (já com a devida configuração contida no zip) para `<eap_dir>/<modules>` (não se aplica a `legacy-slave-hosts`).
- `ext-module-pulp-mafifest-url`: String. Opcional. URL usada para download de módulos especificados em `modules`  (não se aplica a `legacy-slave-hosts`).
- `domain-name`: String. Opcional. Default `<master_hostname> domain`. Nome do domínio.
- `version`: String. Opcional. Default 7.2
- `eap-dir`: String. Opcional. Default `/opt/jboss`. Path que será o link simbólico para o diretório de instalação.
- `is-rpm`: Boolean. Opcional. Default true se version >= 7.0, caso contrário, false.
- `eap-zip-url`: String. Opcional se `is-rpm` = true. URL do pacote zip que contém a instalação do EAP na versão `version`.
- `reinstall`: Boolean. Opcional. Default: false. Faz uninstall seguido de install a cada execução da receita.
- `master-address`: String. Obrigatório. IP do servidor (com o qualificador do domínio) que terá o papel de domain controller (master host). 
- `master-fqdn`: String. Opcional. Nome do servidor (com o qualificador do domínio) que terá o papel de domain controller (master host). Em ambientes com DNS server, se não especificado é descoberto automaticamente.
- `slave-hosts`: List. Identificação do nomes dos slave hosts (sem o qualicador do domínio) que compõem o domínio junto com o master.
- `legacy-slave-hosts`: Hash. Opcional. Configuração de slave hosts adicionais com versão de EAP inferior a do domínio. (testado com EAP 6.4)
- `ldap-role-mappings`: Hash. Opcional (recomendado). Configuração do mapeamento de grupos/usuários LDAP para roles do Jboss.
- `modules`: Hash. Opcional. Usado na instalação de Drivers e configuração de datasources.
- `profiles`: Hash. Configuração de profiles.
- `system-properties`: Hash. Opcional Configuração de system properties com escopo de domínio.


Exemplo:
```json
"jboss": {
  "default-git-base-url": "http://<git_pub_server>/<git_org>/",
  "ext-module-zip-url": "http://<web-server>/jboss-eap-7.2-modules.zip",
  "ext-module-pulp-mafifest-url": "http://<web_server_pulp_repo>/Java_Modules/EAP_7_2/PULP_MANIFEST",
  "domain-name": "Siga Domain",
  "version": "7.2",
  "is-rpm": true,
  "eap-dir": "/opt/jboss",
  "eap-zip-url": "",
  "reinstall": false,
  "master-address": "192.168.0.1",
  "master-fqdn": "meumaster.localdomain",
  "slave-hosts": ["slave71","slave72"],
  "legacy-slave-hosts": {},
  "ldap-role-mappings": {},
  "system-properties": {},
  "modules": {},  
  "profiles": {}
}
```

#### Atributos _complexos_ de `jboss`

Configurando `legacy-slave-hosts`:

Esse atributo é opcional se deseja configurar um domínio sem slave hosts com versões inferiores ao domain controller.

- `<nome_do_host>`: String. Obrigatório. Especifique o nome do host como a chave da configuração do mesmo.
  - `version`: Float. Obrigatório. Versão do legacy slave host especificado.
  - `is-rpm`: Boolean. Opcional. Default true se versão >=7, caso contrário default false.
  - `eap-zip-url`: String. Obrigatório se `is-rpm`= false.
  - `ext-module-zip-url`: String. Opcional. URL usada para download de descompactação de módulos (já com a devida configuração contida no zip) para `<eap_dir>/<modules>`.
  - `ext-module-pulp-mafifest-url`: String. Opcional. URL usada para download de módulos especificados em `modules`.


Exemplo:
```json
{
  "jboss": {
    "legacy-slave-hosts": {
      "slave61": {
        "version": 6.4,
        "is-rpm": false,
        "eap-zip-url": "http://<web-server>/jboss-eap-6.4.22.zip",
        "ext-module-zip-url": "http://<web-server>/jboss-eap-6.4.22-modules.zip",
        "ext-module-pulp-mafifest-url": "http://<web_server_pulp_repo>/Java_Modules/EAP_6_4/PULP_MANIFEST",
      },
      "slave62": {
        "version": 6.4,
        "is-rpm": false,
        "eap-zip-url": "http://<web-server>/jboss-eap-6.4.22.zip",
        "ext-module-zip-url": "http://<web-server>/jboss-eap-6.4.22-modules.zip",
        "ext-module-pulp-mafifest-url": "http://<web_server_pulp_repo>/Java_Modules/EAP_6_4/PULP_MANIFEST",
      }
    }
  }
}
```

Configurando `ldap-role-mapping`:

- `role_name` existentes para configuração: (atenção é "case sensitive"): `Administrator`, `Auditor`, `Deployer`, `Maintainer`, `Monitor`, `Operator` e `SuperUser`
- O usuário adcionado no atributo `pincipal-acc` do databag item ldap_conf será sempre mapeado como `Monitor`.
- Há duas formas de configuração a simplificada e a completa:
  - Simplificada. Assume-se que a role está associada a um GRUPO LDAP.
    `role_name`: [`grupo1`, `grupo2`]
  - Completa. Pode-se especificar grupos ou usuários
    - `role_name`: Hash. Opcional. Fornecer um dos valores válidos.
      - `users`: List. Opcional. Lista com nomes de usuários LDAP
      - `groups`: List. Opcional. Lista com nomes de grupos de usuários LDAP

```json
{
  "jboss": {
    "ldap-role-mapping": {
      "Administrator": ["jb_adm"],
      "Operator": {
        "groups": ["sec_oper"],
        "users": ["user1"]
      },
      "SuperUser": {
        "users": ["jsuperadm"]
      }
    }
  }
}
```


Configurando `system-properties`:

Esse atributo é opcional se deseja configurar system-properties com escopo de domínio. Ele também poderá ser configurado com escopo de server-group com a mesma sintaxe, porém como filho de server-groups.
Para system-porperties cujo boot-time é false, pode ser usada a declaração simplificada `nome_da_system_property: valor_da_system_property`
Para qualquer system-property é possível usar a especificação "completa":
- `nome_da_system_property`: String. Obrigatório chave da especificação (e nome) de uma system property.
  - `value`: String. Obrigatório. Chave para especificação do conteúdo da system property.
  - `boot-time`: Boolean. Opcional. Default false.


Exemplo:
```json
{
  "jboss": {
    "system-properties": {
      "br.example.com.sysprop1": {
        "value": "valor_da_sysprop1",
        "boot-time": true
      },
      "br.example.com.sysprop2": "valor_da_sysprop2"
    }
  }
}
```

Configurando `modules`:
Testado apenas para datasources (jdbc drivers)
- `group`: String. Opcional. Usado para filtro do junto ao nome do arquivo para download no pulp repo (`group/filename`).
- `file`: String. Obrigatório.
- `driver-module-name`: String. Obrigatório. Usado na configuração do módulo e data-source se for o caso.
- Todos os outros são: String. Obrigatórios para datasources.


Exemplo:
```json
{
  "jboss": {
    "modules": {
      "com.microsoft": {
        "driver-name": "com.microsoft",
        "driver-module-name": "com.microsoft",
        "driver-class-name": "com.microsoft.sqlserver.jdbc.SQLServerDriver",
        "driver-xa-datasource-class-name": "com.microsoft.sqlserver.jdbc.SQLServerXADataSource",
        "group": "",
        "file": "sqljdbc4.jar"
      },
      "com.oracle": {
        "driver-name": "com.oracle",
        "driver-module-name": "com.oracle",
        "driver-class-name": "oracle.jdbc.driver.OracleDriver",
        "driver-xa-datasource-class-name": "oracle.jdbc.xa.client.OracleXADataSource",
        "group": "",
        "file": "ojdbc6.jar"
      }
    }
  }
}
```


Configura-se profiles do domínio através de `profiles`. 
- Não utilize nomes de profiles presentes na instalação default (default, ha, full, full-ha).
- Configure pelo menos 1 profile por versão de slave, pois não devem ser "misturados" num mesmo profile/server-group slaves de versões diferentes (nomes de `slave-hosts` com nomes de `legacy-slave-hosts`).
- `nome_do_profile`: Hash. Obrigatório. Nome do profile
  - `src-profile-name`: String. Opcional. Default 'ha' (é o testado). Profile da instalação default a partir do qual o profile será criado.
  - `use-local-hibernate-cache`: Boolean. Opcional. Default true. Substitui no subsistema infinispan por local-cache. Não recomendado trocar a configuração após 1 execução sem `reinstall` true.
  - `use-local-server-cache`: Boolean. Opcional. Default true. Substitui no subsistema infinispan por local-cache. Não recomendado trocar a configuração após 1 execução sem `reinstall` true.
  - `use-local-ejb-cache`: Boolean. Opcional. Default true. Substitui no subsistema infinispan por local-cache. Não recomendado trocar a configuração após 1 execução sem `reinstall` true.
  - `use-local-web-cache`: Boolean. Opcional. Default true. Substitui no subsistema infinispan por local-cache. Não recomendado trocar a configuração após 1 execução sem `reinstall` true.
  - `activemq-pass`: String. Obrigatório se `src-profile-name` ~ /^full/. Senha do sistema messaging-activemq.
  - `cluster-address`: Lista de servidores web apache com mod_cluster na porta 6666 que serão utilizados nesse profile. Essa receita não usa advertise para adição dinâmica com multicast. É utilizado apenas lista de proxy.
  - `webservice-ext-fqdn`: String. Obrigatório. Nome do servidor/serviço que será configurado no subsistema de webservices do profile.
  - `security-domains`: Hash. Opcional. Configuração de security domains do subsistema (legado) security.
  - `data-sources`: Hash. Opcional. Configuração de datasources. (Atenção para instalação de drivers através de `modules`)
  - `server-groups`: Hash. Obrigatório. Configuração de server-groups.


Exemplo:
```json
{
  "jboss": {
    "profiles": {
      "sigadoc": {
        "src-profile-name": "ha",
        "cluster-address": [],
        "webservice-ext-fqdn": "siga72.example.com",
        "security-domains": {},
        "data-sources": {},
        "server-groups": {},
      },
      "sigaEAP6": {
        ...
      }
    }
  }
}
```

Especificação de `security-domains`:

`nome_do_security_domain`: Hash. Obrigatório. Configuração do security domain com o nome especificado na chave.
  `code`: String. Obrigatório. Opções disponíveis no EAP para security domains.
  `flag`: String. Obrigatório. Opções Disponíveis no EAP para security domains.
  `module-options`: Hash. Opcional. Opções Disponíveis no EAP para o security domain configurado.


Exemplo:
```json
{
  "jboss": {
    "profiles": {
      "sigadoc": {
        "security-domains": {
          "sd1": {
            "code": "org.picketlink.identity.federation.bindings.jboss.auth.SAML2LoginModule",
            "flag": "required",
          },
          "sd2":{
            "code": "Database",
            "flag": "required",
            "module-options": {
              "dsJndiName": "java:/jboss/datasources/XXXXX",
              "principalsQuery": "a select statement",
              "hashAlgorithm": "an available hash algotithm",
              "hashEncoding": "an available hash encoding",
              "rolesQuery": "a role query"
            },
          }
        }
      }
    }
  }
}
```


Especificação de `data-sources`:

A receita criará um security domain para cada datasource com as credenciais de autenticação. Recomenda-se o uso de encrypted databags para guardar as credenciais em vez de json de configuração em "clear-text". O databag deverá ter o mesmo nome do datasource e os itens `user-name` e `password`, do contrário a receita tentará pegar os valores desses atributos do json da configuração do datasource.
- `nome_do_datasource`: Hash. Obrigatório. Configuração de um datasource com o nome especificado na chave.
  - `jndi-name`: String. Obrigatório.
  - `driver-name`: String. Obrigatório.
  - `connection-url`: String. Obrigatório.
  - `user-name`: String. Obrigatório se não existir um (encrypted) databag com o mesmo nome do datasource contendo um databag item com as mesmas especificações desse atributo.
  - `password`: String. Obrigatório se não existir um (encrypted) databag com o mesmo nome do datasource contendo um databag item com as mesmas especificações desse atributo.
  - `enabled`: Boolean. Obrigatório.
  - `max-pool-size`: Integer. Obrigatório.
  - `min-pool-size`: Integer. Obrigatório.


Exemplo:
```json
{
  "jboss": {
    "profiles": {
      "sigadoc": {
        "data-sources": {
          "sigaDS1": {
            "jndi-name": "java:/jboss/datasources/sigaDS1",
            "driver-name": "com.mysql",
            "connection-url": "jdbc:mysql://meuservidormysql.example.com:3306/meusigadb",
            "user-name": "mysigauser",
            "password": "mysigapass",
            "enabled": true,
            "max-pool-size": 10,
            "min-pool-size": 1
          },
          "sigaDS1": {
            "jndi-name": "java:/jboss/datasources/sigaDS2",
            "driver-name": "com.oracle",
            "connection-url": "jdbc:oracle:thin:@meuservidororacle.example.com:1521:meuOracleService",
            "user-name": "orasigauser",
            "password": "orasigapass",
            "enabled": true,
            "max-pool-size": 10,
            "min-pool-size": 1
          }
        }
      }
    }
  }
}
```

Especificação de `server-groups`:

- Não devem ser "misturados" num mesmo profile/server-group com slaves de versões diferentes (nomes de `slave-hosts` com nomes de `legacy-slave-hosts`).

- `nome_do_server_group`: Hash. Obrigatório. Nome do server-group
  - `profile`: String. Obrigatório. Nome do profile (tá repetido aqui, depois vemos isso...)
  - `slave-hosts`: List. Opcional. Default = todos `slave-hosts`do domínio exceto os `legacy-slave-hosts`. Limitar os hosts que possuem servers desse servergroup. Pode conter nomes de `legacy-lave-hosts`. 
  - `socket-binding-port-offset`: Integer. Obrigatório.
  - `socket-binding-group`: String. Utilize um dos padrões do jboss (ha-sockets ou full-ha-sockets são os recomendados). Para EAP7.2 em coexistência com EAP6, utilize "eap6-standard-sockets" no server-group EAP6.
  - `heap-size`: String.
  - `max-heap-size`: String.
  - `permgen-size`: String.
  - `max-permgen-size`: String.


Exemplo: 
```json
{
  "jboss": {
    "profiles": {
      "sigadoc": {
        "server-groups": {
          "siga": {
            "profile": "sigadoc",
            "slave-hosts": ["slave71"],
            "socket-binding-port-offset": 0,
            "socket-binding-group": "ha-sockets",
            "heap-size": "1024m",
            "max-heap-size": "1536m",
            "permgen-size": "128m",
            "max-permgen-size": "256m"
          },
          "sigaex": {
            "profile": "sigadoc",
            "slave-hosts": ["slave71", "slave72"],
            "socket-binding-port-offset": 100,
            "socket-binding-group": "ha-sockets",
            "heap-size": "1024m",
            "max-heap-size": "1536m",
            "permgen-size": "128m",
            "max-permgen-size": "256m"
          }
        },
        "sigaEAP6": {
        "server-groups": {
          "sigasr": {
            "profile": "sigaEAP6",
            "slave-hosts": ["slave61"],
            "socket-binding-port-offset":200,
            "socket-binding-group": "eap6-standard-sockets",
            "heap-size": "1024m",
            "max-heap-size": "1536m",
            "permgen-size": "128m",
            "max-permgen-size": "256m"
          },
          "sigagcpp": {
            "profile": "sigaEAP6",
            "slave-hosts": ["slave62"],
            "socket-binding-port-offset": 300,
            "socket-binding-group": "eap6-standard-sockets",
            "heap-size": "1024m",
            "max-heap-size": "1536m",
            "permgen-size": "128m",
            "max-permgen-size": "256m"
          }
        }
      }
    }
  }
}
```


## Uso

Como explicado, o uso da receita é bem simples. Basta aplicar ao host a receita `jboss-eap::eap7` que o jboss será instalado e configurado conforme declaração json sobre o domínio.
