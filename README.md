slapo-lua_hook
==============

### Intro

This overlay was made while I began reading about Lua and that was a pretext to a dig a bit into OpenLDAP's code.  
So it may not fulfill your expectations (if any).

This overlay structure was inspired by [slapo-auditlog](http://www.openldap.org/software/man.cgi?query=slapo-auditlog&apropos=0&sektion=0&manpath=OpenLDAP+2.4-Release&format=html).

The Makefile is taken from some overlays in _contrib/slapd-modules_, so you may need to tweak it.  
This overlay only work with Lua 5.2 and has been tested on Debian.

### Configuration examples

_cn=config_ example (to be ldapadd'd):
```
dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulePath: /srv/openldap/lib/modules # you may need to change this
olcModuleLoad: lua_hook.so

dn: olcOverlay=lua_hook,olcDatabase={-1}frontend,cn=config
objectClass: olcOverlayConfig
objectClass: olcLuaHookConfig
olcOverlay: lua_hook
olcLuaHookFile: /tmp/dumper.lua # changing this attribute will reload the lua script
olcLuaHookFunction: dump # however changing this one will not reload the lua script
```

If the file or the function could not be loaded for the current operation, the file will be entirely reloaded next time.

#### Simple Lua file
Grab the DataDumper function [here](http://lua-users.org/files/wiki_insecure/dumper.lua).
```
-- DataDumper function should be put here

local function dump(self, data)
  self.i = self.i + 1 -- the overlay will pass the module table as first parameter
  print("request " .. self.i)
  print(DataDumper(data, "operation=")) -- the overlay will pass the operation data as the second one
end

local module = {}
module.i = 0
module.dump = dump -- olcLuaHookFunction is the key to be checked in the table

return module -- the overlay only allow a table to be returned or will warn
```

### Some output examples

#### A delete operation
```
5443569e send_ldap_result: conn=1000 op=1 p=3
5443569e lua_hook: processing operation type: 0x4a (LDAP_REQ_DELETE)
5443569e lua_hook: lua script changed ((null) -> /tmp/dumper.lua)
5443569e lua_hook: loading file /tmp/dumper.lua...
5443569e lua_hook: loading function dump...
request 1
operation={
  changetype="delete",
  connection={
    dn="cn=ether,dc=lethe,dc=fr",
    id=1000,
    peer="IP=[::1]:45457",
    suffix="dc=lethe,dc=fr"
  },
  dn="uid=test,dc=lethe,dc=fr"
}
5443569e lua_hook: time spent in mutex: 1.333ms
5443569e lua_hook: time spent in lua function: 0.669ms
5443569e lua_hook: time spent in preprocessing lua function: 0.664ms
5443569e send_ldap_response: msgid=2 tag=107 err=0
```

#### An add operation
```
544356a0 send_ldap_result: conn=1001 op=1 p=3
544356a0 lua_hook: processing operation type: 0x68 (LDAP_REQ_ADD)
544356a0 lua_hook: loading function dump...
request 2
operation={
  attributes={
    { attribute="objectClass", values={ "posixAccount", "inetOrgPerson" } },
    { attribute="uid", values={ "test" } },
    { attribute="givenName", values={ "test" } },
    { attribute="cn", values={ "test" } },
    { attribute="sn", values={ "test" } },
    { attribute="homeDirectory", values={ "/tmp/test" } },
    { attribute="uidNumber", values={ "0" } },
    { attribute="gidNumber", values={ "0" } },
    { attribute="structuralObjectClass", values={ "inetOrgPerson" } },
    { attribute="entryUUID", values={ "d7815ea4-eba2-1033-88e8-ebf80ab0175d" } },
    { attribute="creatorsName", values={ "cn=ether,dc=lethe,dc=fr" } },
    { attribute="createTimestamp", values={ "20141019061352Z" } },
    { attribute="entryCSN", values={ "20141019061352.005245Z#000000#000#000000" } },
    { attribute="modifiersName", values={ "cn=ether,dc=lethe,dc=fr" } },
    { attribute="modifyTimestamp", values={ "20141019061352Z" } }
  },
  changetype="add",
  connection={
    dn="cn=ether,dc=lethe,dc=fr",
    id=1001,
    peer="IP=[::1]:45458",
    suffix="dc=lethe,dc=fr"
  },
  dn="uid=test,dc=lethe,dc=fr"
}
544356a0 lua_hook: time spent in mutex: 0.497ms
544356a0 lua_hook: time spent in lua function: 0.452ms
544356a0 lua_hook: time spent in preprocessing lua function: 0.045ms
544356a0 send_ldap_response: msgid=2 tag=105 err=0
```

#### A modify operation
```
544356bd send_ldap_result: conn=1002 op=1 p=3
544356bd lua_hook: processing operation type: 0x66 (LDAP_REQ_MODIFY)
544356bd lua_hook: loading function dump...
544356bd lua_hook: processing modification type: 0x2 (LDAP_MOD_REPLACE)
544356bd lua_hook: processing modification type: 0x2 (LDAP_MOD_REPLACE)
544356bd lua_hook: processing modification type: 0x2 (LDAP_MOD_REPLACE)
544356bd lua_hook: processing modification type: 0x2 (LDAP_MOD_REPLACE)
request 3
operation={
  changetype="modify",
  connection={
    dn="cn=ether,dc=lethe,dc=fr",
    id=1002,
    peer="IP=[::1]:45459",
    suffix="dc=lethe,dc=fr"
  },
  dn="uid=test,dc=lethe,dc=fr",
  modifications={
    { attribute="description", modification="replace", values={ "test2", "test1" } },
    {
      attribute="entryCSN",
      modification="replace",
      values={ "20141019061421.222514Z#000000#000#000000" }
    },
    {
      attribute="modifiersName",
      modification="replace",
      values={ "cn=ether,dc=lethe,dc=fr" }
    },
    {
      attribute="modifyTimestamp",
      modification="replace",
      values={ "20141019061421Z" }
    }
  }
}
544356bd lua_hook: time spent in mutex: 0.196ms
544356bd lua_hook: time spent in lua function: 0.168ms
544356bd lua_hook: time spent in preprocessing lua function: 0.028ms
544356bd send_ldap_response: msgid=2 tag=103 err=0
```

#### A modrdn operation
```
544356ce send_ldap_result: conn=1003 op=1 p=3
544356ce lua_hook: processing operation type: 0x6c (LDAP_REQ_MODRDN)
544356ce lua_hook: loading function dump...
request 4
operation={
  changetype="modrdn",
  connection={
    dn="cn=ether,dc=lethe,dc=fr",
    id=1003,
    peer="IP=[::1]:45460",
    suffix="dc=lethe,dc=fr"
  },
  deleteoldrdn=-1,
  dn="uid=test,dc=lethe,dc=fr",
  newrdn="uid=test"
}
544356ce lua_hook: time spent in mutex: 0.128ms
544356ce lua_hook: time spent in lua function: 0.114ms
544356ce lua_hook: time spent in preprocessing lua function: 0.014ms
544356ce send_ldap_response: msgid=2 tag=109 err=0
```

#### An operation not implemented (a bind)
```
544356ce send_ldap_result: conn=1003 op=0 p=3
544356ce lua_hook: unknown operation type: 0x60
544356ce send_ldap_response: msgid=1 tag=97 err=0
```

### Notes
Since Lua is not threadsafe, all Lua calls are enclosed in a mutex.  
If you do not want the time spent statistics, remove -DLUA_HOOK_TIME_SPENT.  
Currently, only four operations (the one that modify data) are supported: LDAP_REQ_ADD, LDAP_REQ_MODIFY, LDAP_REQ_DELETE, LDAP_REQ_MODRDN, it should be easy to support more.  

This overlay was juste made for 'fun' :)
