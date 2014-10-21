/* lua_hook.c - transmit some operations data to a Lua script */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005-2014 The OpenLDAP Foundation.
 * Portions copyright 2004-2005 Symas Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#ifdef SLAPD_OVER_LUA_HOOK

#include "slap.h"
#include "config.h"

#ifdef LUA_HOOK_TIME_SPENT
  #include <sys/time.h>
#endif

#include <string.h>

#include <lua5.2/lua.h>
#include <lua5.2/lauxlib.h> /* luaL_* */
#include <lua5.2/lualib.h> /* luaL_openlibs */

#define TUPLE(s) s, #s

/* our overlay data state */
typedef struct lua_hook_data {
  ldap_pvt_thread_mutex_t lh_mutex; /* see in ldap_{pvt,int}_thread.h */
  char *lh_file;
  char *lh_current_file;
  char *lh_function;
  lua_State *lh_lua;
} lua_hook_data;

/* defined in slapd.h */
static ConfigTable lua_hook_cfg[] = { {
    .name = "lua_hook-script",
    .what = "filename",
    .min_args = 2,
    .max_args = 2,
    .length = 0,
    .arg_type = ARG_STRING | ARG_OFFSET, /* defined in config.h */
    .arg_item = (void *)offsetof(lua_hook_data, lh_file),
    .attribute = "( OLcfgOvAt:22.1 NAME 'olcLuaHookFile' "
                 "DESC 'Lua script loaded by lua_hook' "
                 "SYNTAX OMsDirectoryString )",
    /* remainder:
    .ad = NULL,
    .notify = NULL, */
  }, {
    .name = "lua_hook-function",
    .what = "function",
    .min_args = 2,
    .max_args = 2,
    .length = 0,
    .arg_type = ARG_STRING | ARG_OFFSET, /* defined in config.h */
    .arg_item = (void *)offsetof(lua_hook_data, lh_function),
    .attribute = "( OLcfgOvAt:22.2 NAME 'olcLuaHookFunction' "
                 "DESC 'Lua function called by lua_hook' "
                 "SYNTAX OMsDirectoryString )",
    /* remainder:
    .ad = NULL,
    .notify = NULL, */
  }, {
    NULL, NULL, 0, 0, 0, ARG_IGNORED, /* everything else default to null */
  }
};

/* defined in slapd.h */
static ConfigOCs lua_hook_ocs[] = { {
    .co_def = "( OLcfgOvOc:22.1 NAME 'olcLuaHookConfig' "
              "DESC 'Lua Hook configuration' "
              "SUP olcOverlayConfig "
              "MUST ( olcLuaHookFile $ olcLuaHookFunction ) )",
    .co_type = Cft_Overlay, /* defined in config.h */
    .co_table = lua_hook_cfg,
    /* remainder:
    .co_ldadd = NULL,
    .co_cfadd = NULL,
#ifdef SLAP_CONFIG_DELETE
    .co_lddel = NULL,
#endif
    .co_oc = NULL,
    .co_name = NULL, */
  }, {
    NULL, 0, NULL, /* everything else default to null */
  }
};

/* helper to clear Lua stack */
inline static void lua_stack_clear(lua_State *lua) {
  int stack_size = lua_gettop(lua);
  if (stack_size) {
    lua_pop(lua, stack_size);
    Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG,
         "lua_hook: stack have been cleared, size was: %d\n",
         stack_size);
  }
}

/* helper to load a Lua script */
inline static int lua_hook_load_file(lua_State *lua, const char *file) {
  Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG,
       "lua_hook: loading file %s...\n", file);

  /* load the file */
  if (luaL_loadfile(lua, file) != LUA_OK) {
    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: file %s could not be loaded (%s)\n",
         file, lua_tostring(lua, -1));
    lua_stack_clear(lua);
    return -1;
  }

  /* execute the loaded chunk */
  if (lua_pcall(lua, 0, 1, 0) != LUA_OK) {
    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: chunk loaded from file %s could not be executed (%s)\n",
         file, lua_tostring(lua, -1));
    lua_stack_clear(lua);
    return -1;
  }

  /* chunk must return a table */
  if (!lua_istable(lua, -1)) {
    Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: chunk loaded from file %s did not return a table\n", file);
    lua_stack_clear(lua);
    return -1;
  }
  return 0;
}

/* helper to retrive a function under a specific table key */
inline static int lua_hook_load_function(lua_State *lua, const char *function) {
  Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG,
       "lua_hook: loading function %s...\n", function);

  lua_getfield(lua, -1, function);
  if (!lua_isfunction(lua, -1)) {
    Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: table returned from loaded chunk "
         "does not have a function under the '%s' key\n", function);
    lua_stack_clear(lua);
    return -1;
  }
  return 0;
}

/* helper to add a stringto a table under a string key */
inline static void lua_table_add_string(
  lua_State *lua, const char *key, const char *value
) {
  if (value) {
    lua_pushstring(lua, value);
    lua_setfield(lua, -2, key);
  }
}

/* helper to add a int to a table under a string key */
inline static void lua_table_add_int(
  lua_State *lua, const char *key, int value
) {
  lua_pushinteger(lua, value);
  lua_setfield(lua, -2, key);
}

/* helper to add a string into an array, indexing start at 1 */
inline static void lua_array_add_string(
  lua_State *lua, int key, const char *value
) {
  lua_pushinteger(lua, key);
  lua_pushstring(lua, value);
  lua_settable(lua, -3);
}

/* modrdn operation */
inline static struct berval *lua_hook_req_modrdn(
  lua_hook_data *lh, Operation *op
) {
  lua_table_add_string(lh->lh_lua, "changetype", "modrdn");
  lua_table_add_string(lh->lh_lua, "newrdn", op->orr_newrdn.bv_val);
  lua_table_add_int(lh->lh_lua, "deleteoldrdn", op->orr_deleteoldrdn);
  if (op->orr_newSup) {
    lua_table_add_string(lh->lh_lua, "newsuperior", op->orr_newSup->bv_val);
  }
  return NULL;
}

/* delete operation */
inline static struct berval *lua_hook_req_delete(
  lua_hook_data *lh, Operation *op
) {
  lua_table_add_string(lh->lh_lua, "changetype", "delete");
  return NULL;
}

/* add operation */
inline static struct berval *lua_hook_req_add(
  lua_hook_data *lh, Operation *op
) {
  Attribute *a;
  struct berval *b, *dn = NULL;
  int add = 0, i;

  /* we should get something like that:
     { changetype=add,
     attributes={1={attribute=a, values={x,y,z}},
     2=...}} */
  lua_table_add_string(lh->lh_lua, "changetype", "add");

  /* create an array to host every addition
     {} */
  lua_newtable(lh->lh_lua);

  for (a = op->ora_e->e_attrs; a; a = a->a_next) {
    if (a->a_desc == slap_schema.si_ad_modifiersName) {
      dn = &a->a_vals[0];
    }

    b = a->a_vals;
    if (b) {
      /* the index of our array
         {1=} */
      lua_pushinteger(lh->lh_lua, add++ + 1);
      /* create a table to host this addition
         {} */
      lua_newtable(lh->lh_lua);
      /* fill the attribute key
         {attribute=...} */
      lua_table_add_string(lh->lh_lua,
                           "attribute", a->a_desc->ad_cname.bv_val);
      /* create an array to host every value for that attribute
         {} */
      lua_newtable(lh->lh_lua);
      for (i = 0; b[i].bv_val; i++) {
        /* add each value for this attribute to the array
           {x,y,z} */
        lua_array_add_string(lh->lh_lua, i + 1, b[i].bv_val);
      }
      /* now that we got our array, fill the values key
         {attribute=..., values={x,y,z}} */
      lua_setfield(lh->lh_lua, -2, "values");
      /* push the attribute/values table into our main array
         {1={attribute=..., values={x,y,z}}} */
      lua_settable(lh->lh_lua, -3);
    }
  }
  /* put the array of attribute/values tables under the attributes key
     { changetype=add,
     attributes={1={attribute=..., values={x,y,z}}
     2=...}} */
  lua_setfield(lh->lh_lua, -2, "attributes");
  return dn;
}

/* modify operation */
inline static struct berval *lua_hook_req_modify(
  lua_hook_data *lh, Operation *op
) {
  Modifications *m;
  struct berval *b, *dn = NULL;
  int modify = 0, i, modification;
  /* quick and dirty pair type/string for each supported modification */
  struct modifications_switch {
    int sm_op;
    const char *str_sm_op;
    const char *type;
  } modifications[] = {
    {TUPLE(LDAP_MOD_ADD), "add"},
    {TUPLE(LDAP_MOD_DELETE), "delete"},
    {TUPLE(LDAP_MOD_REPLACE), "replace"},
    {TUPLE(LDAP_MOD_INCREMENT), "increment"},
  };

  /* we should get something like that:
     { changetype=modify,
     modifications={1={modification=add|replace|...,
     attribute=a,
     values={x,y,z}},
     2=...}} */
  lua_table_add_string(lh->lh_lua, "changetype", "modify");

  /* create an array to host every modification
     {} */
  lua_newtable(lh->lh_lua);

  for (m = op->orm_modlist; m; m = m->sml_next) {
    if (m->sml_desc == slap_schema.si_ad_modifiersName &&
        (m->sml_op == LDAP_MOD_ADD || m->sml_op == LDAP_MOD_REPLACE)) {
      dn = &m->sml_values[0];
    }

    modification = m->sml_op & LDAP_MOD_OP;
    /* test that the modification is supported */
    for (i = 0;
         i < sizeof(modifications) / sizeof(struct modifications_switch)
           && modifications[i].sm_op != modification;
         i++);
    /* not a supported modification */
    if (i >= sizeof(modifications) / sizeof(struct modifications_switch)) {
      Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_WARNING,
           "lua_hook: unknown modification type: %02x\n", modification);
      continue;
    }

    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG,
         "lua_hook: processing modification type: %#02x (%s)\n",
         modifications[i].sm_op, modifications[i].str_sm_op);

    /* the index of our array
       {1=} */
    lua_pushinteger(lh->lh_lua, modify++ + 1);
    /* create table to host this modification
       {} */
    lua_newtable(lh->lh_lua);
    /* fill the modification key
       {modification=...} */
    lua_table_add_string(lh->lh_lua, "modification", modifications[i].type);
    /* fill the attribute key
       {modification=...,
       attribute=...} */
    lua_table_add_string(lh->lh_lua,
                         "attribute", m->sml_desc->ad_cname.bv_val);

    b = m->sml_values;
    if (b) {
      /* create an array to host every value for that attribute
         {} */
      lua_newtable(lh->lh_lua);
      for (i = 0; b[i].bv_val; i++) {
        /* add each value for this attribute to the array
           {x,y,z} */
        lua_array_add_string(lh->lh_lua, i + 1, b[i].bv_val);
      }
      /* now that we got our array, fill the values key
         {modification=...,
         attribute=...,
         values={x,y,z}} */
      lua_setfield(lh->lh_lua, -2, "values");
    }
    /* push the modification/attribute[/values] table into our main array
       {1={modification=...,
       attribute=...,
       values={x,y,z}} */
    lua_settable(lh->lh_lua, -3);
  }
  lua_setfield(lh->lh_lua, -2, "modifications");
  return dn;
}

/* create a structure with connection informations */
inline static void lua_hook_connection_infos(
  lua_hook_data *lh, Operation *op, struct berval *dn
) {
  /* we should get something like that:
     { peer=...,
       id=...,
       dn=...,
       real_dn=...,
       connection=...,
       suffix=...} */
  lua_newtable(lh->lh_lua);
  lua_table_add_string(lh->lh_lua, "peer", op->o_conn->c_peer_name.bv_val);
  lua_table_add_string(lh->lh_lua, "suffix", op->o_bd->be_suffix[0].bv_val);
  lua_table_add_int(lh->lh_lua, "id", op->o_conn->c_connid);
  lua_table_add_string(lh->lh_lua, "dn", dn->bv_val);
  /* what is this for? */
  if (!BER_BVISEMPTY(&op->o_conn->c_dn) &&
      (!dn || !dn_match(dn, &op->o_conn->c_dn))) {
    lua_table_add_string(lh->lh_lua, "real_dn", op->o_conn->c_dn.bv_val);
  }
  /* now that we got the connection related stuff, push it in the main table */
  lua_setfield(lh->lh_lua, -2, "connection");
}

#ifdef LUA_HOOK_TIME_SPENT
inline static double lua_hook_elapsed_time(
  struct timeval *start, struct timeval *end
) {
  double elapsed_time;

  elapsed_time = (end->tv_sec - start->tv_sec) * 1000.;
  elapsed_time += (end->tv_usec - start->tv_usec) / 1000.;
  return elapsed_time;
}
#endif

static int lua_hook_response(Operation *op, SlapReply *rs) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  lua_hook_data *lh = on->on_bi.bi_private;
  struct berval *dn = NULL;
  /* quick and dirty pair type/function for each supported operation */
  struct operations_switch {
    ber_tag_t o_tag;
    const char *str_o_tag;
    struct berval *(*handler)(lua_hook_data *, Operation *);
  } operations[] = {
    {TUPLE(LDAP_REQ_ADD), lua_hook_req_add},
    {TUPLE(LDAP_REQ_MODIFY), lua_hook_req_modify},
    {TUPLE(LDAP_REQ_DELETE), lua_hook_req_delete},
    {TUPLE(LDAP_REQ_MODRDN), lua_hook_req_modrdn},
  };
  int i;
#ifdef LUA_HOOK_TIME_SPENT
  struct timeval hook_start, function_start, hook_end;
  double time_mutex, time_function, time_preprocess;
#endif

  /* prerequisites for our hook */
  if (rs->sr_err != LDAP_SUCCESS || !lh->lh_file || !lh->lh_function) {
    return SLAP_CB_CONTINUE;
  }

  /* test that the operation is supported */
  for (i = 0;
       i < sizeof(operations) / sizeof(struct operations_switch) &&
         operations[i].o_tag != op->o_tag;
       i++);
  /* not a supported operation */
  if (i >= sizeof(operations) / sizeof(struct operations_switch)) {
    Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_WARNING,
         "lua_hook: unknown operation type: %#02x\n", op->o_tag);
    return SLAP_CB_CONTINUE;
  }

  Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG,
       "lua_hook: processing operation type: %#02x (%s)\n",
       operations[i].o_tag, operations[i].str_o_tag);

#ifdef LUA_HOOK_TIME_SPENT
  gettimeofday(&hook_start, NULL);
#endif

  /* this is a supported operation, we can lock now */
  ldap_pvt_thread_mutex_lock(&lh->lh_mutex);

  /* if the file to be loaded has changed */
  if (!lh->lh_current_file || strcmp(lh->lh_file, lh->lh_current_file)) {
    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG,
         "lua_hook: lua script changed (%s -> %s)\n",
         lh->lh_current_file, lh->lh_file);

    free(lh->lh_current_file);
    lh->lh_current_file = ch_strdup(lh->lh_file);
    lua_stack_clear(lh->lh_lua);
  }

  /* lua stack is empty, nothing has been loaded yet, so load the file */
  if (!lua_gettop(lh->lh_lua) && lua_hook_load_file(lh->lh_lua, lh->lh_file)) {
    ldap_pvt_thread_mutex_unlock(&lh->lh_mutex);
    return SLAP_CB_CONTINUE;
  }

  /* load on the top of the stack the desired function to call */
  if (lua_hook_load_function(lh->lh_lua, lh->lh_function)) {
    ldap_pvt_thread_mutex_unlock(&lh->lh_mutex);
    return SLAP_CB_CONTINUE;
  }
  /* copy the table module as the first parameter of the function */
  lua_pushvalue(lh->lh_lua, -2);

  /* create the table that will get the operation infos */
  lua_newtable(lh->lh_lua);

  /* fill the dn key */
  lua_table_add_string(lh->lh_lua, "dn", op->o_req_dn.bv_val);

  /* add or modify: use modifiersName as dn if present */
  dn = operations[i].handler(lh, op);
  /* note: this means requestor's dn when modifiersName is null */
  if (!dn) {
    dn = &op->o_dn;
  }

  /* add to the main table the connection infos */
  lua_hook_connection_infos(lh, op, dn);

#ifdef LUA_HOOK_TIME_SPENT
  gettimeofday(&function_start, NULL);
#endif

  /* call function(module_table, operation_infos) */
  if (lua_pcall(lh->lh_lua, 2, 0, 0) != LUA_OK) {
    Log2(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: error while executing function under the key '%s' (%s)\n",
         lh->lh_function, lua_tostring(lh->lh_lua, -1));
    lua_stack_clear(lh->lh_lua);
  }

  /* we are done with lua, unlock the mutex */
  ldap_pvt_thread_mutex_unlock(&lh->lh_mutex);

#ifdef LUA_HOOK_TIME_SPENT
  gettimeofday(&hook_end, NULL);
  time_mutex = lua_hook_elapsed_time(&hook_start, &hook_end);
  time_function = lua_hook_elapsed_time(&function_start, &hook_end);
  time_preprocess = time_mutex - time_function;
  Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, 
       "lua_hook: time spent in mutex: %.3fms\n",
       time_mutex);
  Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
       "lua_hook: time spent in lua function: %.3fms\n",
       time_function);
  Log1(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO,
       "lua_hook: time spent in preprocessing lua function: %.3fms\n",
       time_preprocess);
#endif

  return SLAP_CB_CONTINUE;
}

static int lua_hook_db_init(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  lua_hook_data *lh = ch_calloc(1, sizeof(lua_hook_data));

  on->on_bi.bi_private = lh;
  ldap_pvt_thread_mutex_init(&lh->lh_mutex);
  lh->lh_lua = luaL_newstate();
  if (!lh->lh_lua) {
    Log0(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: could not create a lua state");
    return -1;
  }
  luaL_openlibs(lh->lh_lua);
  Log0(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG, "lua_hook: bi_db_init()\n");
  return 0;
}

static int lua_hook_db_destroy(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  lua_hook_data *lh = on->on_bi.bi_private;

  lua_close(lh->lh_lua);
  ldap_pvt_thread_mutex_destroy(&lh->lh_mutex);
  free(lh->lh_file);
  free(lh->lh_current_file);
  free(lh->lh_function);
  free(lh);
  Log0(LDAP_DEBUG_ANY, LDAP_LEVEL_DEBUG, "lua_hook: bi_db_destroy()\n");
  return 0;
}

/* our overlay structure */
static slap_overinst lua_hook;

/* how is this function called in static linking? */
int lua_hook_initialize(void) {
  lua_hook.on_bi.bi_type = "lua_hook";
  lua_hook.on_bi.bi_db_init = lua_hook_db_init;
  lua_hook.on_bi.bi_db_destroy = lua_hook_db_destroy;
  lua_hook.on_response = lua_hook_response;
  lua_hook.on_bi.bi_cf_ocs = lua_hook_ocs;
  int rc = config_register_schema(lua_hook_cfg, lua_hook.on_bi.bi_cf_ocs);
  if (rc) {
    /* may only happen if the overlay schema is modified */
    Log0(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR,
         "lua_hook: config_register_schema() failed\n");
    return rc;
  }
  return overlay_register(&lua_hook);
}

#if SLAPD_OVER_LUA_HOOK == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
  return lua_hook_initialize();
}
#endif

#endif
