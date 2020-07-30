rl_packages
=========

Instalação

Requirements
------------

Declaração da variável var_packages_conf

Role Variables
--------------

  var_packages_conf: Hash/Dict
    - name: String. Nome do pacote. (Pode ser nome-versao)
      state: String. Opcional. present (default) para instalar, ou absent para remover.

Dependencies
------------


Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    ---
  - hosts: localhost
    connection: local
    remote_user: root
    gather_facts: no
    roles:
      - rl_packages
    vars:
      var_packages_conf:
      - name: python-pbr
        state: present
      - name: openjdk-8-jre
        state: absent

License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
