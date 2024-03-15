extern "C"
{
#include <lua.h> 
#include <lauxlib.h> 
#include <lualib.h> 
}

#include "stompc.h"

namespace libstomp
{
    static const char LUA_STOMP[]="stomp::connection*";

    int lua_stomp_connect(lua_State* L);

    int lua_stomp_gc(lua_State* L);
    int lua_stomp_tostring(lua_State* L);
    int lua_stomp_close(lua_State* L);
    int lua_stomp_login(lua_State* L);
    int lua_stomp_logout(lua_State* L);
    int lua_stomp_subscribe(lua_State* L);
    int lua_stomp_unsubscribe(lua_State* L);
    int lua_stomp_ack(lua_State* L);
    int lua_stomp_recv(lua_State* L);
    int lua_stomp_send(lua_State* L);
}


extern "C" int luaopen_luastomp(lua_State* L)
{
    static const luaL_Reg lib[]=
    {
        {"connect",libstomp::lua_stomp_connect},
        {0,0}
    };

    static const luaL_Reg clib[]=
    {
        {"__gc",libstomp::lua_stomp_gc},
        {"__tostring",libstomp::lua_stomp_tostring},
        {"close",libstomp::lua_stomp_close},
        {"login",libstomp::lua_stomp_login},
        {"logout",libstomp::lua_stomp_logout},
        {"subscribe",libstomp::lua_stomp_subscribe},
        {"unsubscribe",libstomp::lua_stomp_unsubscribe},
        {"ack",libstomp::lua_stomp_ack},
        {"recv",libstomp::lua_stomp_recv},
        {"send",libstomp::lua_stomp_send},
        {0,0}
    };

    luaL_newmetatable(L,libstomp::LUA_STOMP);
    lua_pushvalue(L,-1);
    lua_setfield(L,-2,"__index");
    luaL_register(L,0,clib);
    luaL_register(L,"stomp",lib);

    return 0;
}

int libstomp::lua_stomp_connect(lua_State* L)
{
    if(lua_gettop(L)>0)
    {
        const char* addr=luaL_checkstring(L,1);

        stomp::connection* con=new stomp::connection;

        if(con->connect(addr))
        {
            stomp::connection** pcon=(stomp::connection**)lua_newuserdata(L,sizeof(stomp::connection*));

            *pcon=con;

            luaL_getmetatable(L,LUA_STOMP);
            lua_setmetatable(L,-2);

            return 1;
        }

        delete con;
    }

    return 0;
}

int libstomp::lua_stomp_gc(lua_State* L)
{
    return lua_stomp_close(L);
}

int libstomp::lua_stomp_close(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    if(*pcon)
        delete *pcon;

    return 0;
}

int libstomp::lua_stomp_tostring(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    if(*pcon)
        lua_pushstring(L,"stomp::connection");
    else
        lua_pushnil(L);

    return 1;
}

int libstomp::lua_stomp_login(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    int rc=0;

    if(*pcon && lua_gettop(L)>2 && (*pcon)->login(luaL_checkstring(L,2),luaL_checkstring(L,3)))
        rc=1;

    lua_pushboolean(L,rc);

    return 1;
}

int libstomp::lua_stomp_logout(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    int rc=0;

    if(*pcon && (*pcon)->logout())
        rc=1;

    lua_pushboolean(L,rc);

    return 1;
}

int libstomp::lua_stomp_subscribe(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    int rc=0;

    if(*pcon && lua_gettop(L)>1 && (*pcon)->subscribe(luaL_checkstring(L,2)))
        rc=1;

    lua_pushboolean(L,rc);

    return 1;
}

int libstomp::lua_stomp_unsubscribe(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    int rc=0;

    if(*pcon && lua_gettop(L)>1 && (*pcon)->unsubscribe(luaL_checkstring(L,2)))
        rc=1;

    lua_pushboolean(L,rc);

    return 1;
}

int libstomp::lua_stomp_ack(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    int rc=0;

    if(*pcon && (*pcon)->ack(lua_gettop(L)>1?luaL_checkstring(L,2):""))
        rc=1;

    lua_pushboolean(L,rc);

    return 1;
}

int libstomp::lua_stomp_recv(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    if(*pcon)
    {
        stomp::frame f;

        if((*pcon)->recv(f))
        {
            lua_newtable(L);

            for(std::map<std::string,std::string>::const_iterator it=f.hdrs.begin();it!=f.hdrs.end();++it)
                { lua_pushstring(L,it->first.c_str()); lua_pushstring(L,it->second.c_str()); lua_rawset(L,-3); }

            lua_pushstring(L,"command");
            lua_pushlstring(L,f.command.c_str(),f.command.length());
            lua_rawset(L,-3);

            lua_pushstring(L,"data");
            lua_pushlstring(L,f.data.c_str(),f.data.length());
            lua_rawset(L,-3);

            return 1;
        }
    }

    lua_pushnil(L);

    return 1;
}

int libstomp::lua_stomp_send(lua_State* L)
{
    stomp::connection** pcon=(stomp::connection**)luaL_checkudata(L,1,LUA_STOMP);

    int rc=0;

    if(*pcon && lua_gettop(L)==2 && lua_type(L,2)==LUA_TTABLE)
    {
        stomp::frame f("SEND");

        lua_pushnil(L);
        while(lua_next(L,-2))
        {
            size_t len=0;
            const char* p=lua_tolstring(L,-1,&len);
            std::string value(p,len); lua_pop(L,1);

            p=lua_tolstring(L,-1,&len);
            std::string name(p,len);

            if(name=="data")
                f.data.swap(value);
            else if(name=="command")
                f.command.swap(value);
            else
                f.hdrs[name].swap(value);
        }

        if((*pcon)->send(f))
            rc=1;
    }

    lua_pushboolean(L,rc);

    return 1;
}
