/*
 *  Copyright (C) 2016 Masatoshi Teruya
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"), 
 *  to deal in the Software without restriction, including without limitation 
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 *  and/or sell copies of the Software, and to permit persons to whom the 
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 *  DEALINGS IN THE SOFTWARE.
 *
 *  lau.h
 *  Created by Masatoshi Teruya on 16/02/06.
 */


#ifndef lua_api_utility_header_h
#define lua_api_utility_header_h

// lualib
#include <lauxlib.h>
#include <lualib.h>


#define LAU_API static inline

/* references */

LAU_API int lau_ref( lua_State *L ){
    return luaL_ref( L, LUA_REGISTRYINDEX );
}


LAU_API int lau_refat( lua_State *L, int idx ){
    lua_pushvalue( L, idx );
    return luaL_ref( L, LUA_REGISTRYINDEX );
}


LAU_API int lau_isref( int ref ){
    return ref >= 0;
}


LAU_API void lau_pushref( lua_State *L, int ref ){
    lua_rawgeti( L, LUA_REGISTRYINDEX, ref );
}


LAU_API int lau_unref( lua_State *L, int ref ){
    luaL_unref( L, LUA_REGISTRYINDEX, ref );
    return LUA_NOREF;
}


LAU_API int lau_setmetatable( lua_State *L, const char *tname ){
    luaL_getmetatable( L, tname );
    return lua_setmetatable( L, -2 );
}


LAU_API void lau_fn2tbl( lua_State *L, const char *k, lua_CFunction v ){
    lua_pushstring( L, k );
    lua_pushcfunction( L, v );
    lua_rawset( L, -3 );
}


LAU_API void lau_str2tbl( lua_State *L, const char *k, const char *v ){
    lua_pushstring( L, k );
    lua_pushstring( L, v );
    lua_rawset( L, -3 );
}


LAU_API void lau_num2tbl( lua_State *L, const char *k, lua_Number v ){
    lua_pushstring( L, k );
    lua_pushnumber( L, v );
    lua_rawset( L, -3 );
}


/* check string argument */
LAU_API const char *lau_checklstring( lua_State *L, int idx, size_t *len )
{
    luaL_checktype( L, idx, LUA_TSTRING );
    return lua_tolstring( L, idx, len );
}


LAU_API const char *lau_optlstring( lua_State *L, int idx, const char *def,
                                    size_t *len )
{
    if( lua_isnoneornil( L, idx ) ){
        return def;
    }

    return lau_checklstring( L, idx, len );
}


LAU_API const char *lau_checkstring( lua_State *L, int idx )
{
    luaL_checktype( L, idx, LUA_TSTRING );
    return lua_tostring( L, idx );
}


LAU_API const char *lau_optstring( lua_State *L, int idx, const char *def )
{
    if( lua_isnoneornil( L, idx ) ){
        return def;
    }

    return lau_checkstring( L, idx );
}


/* check integer argument */
LAU_API lua_Integer lau_checkinteger( lua_State *L, int idx )
{
    luaL_checktype( L, idx, LUA_TNUMBER );
    return lua_tointeger( L, idx );
}


LAU_API lua_Integer lau_optinteger( lua_State *L, int idx, lua_Integer def )
{
    if( lua_isnoneornil( L, idx ) ){
        return def;
    }

    return lau_checkinteger( L, idx );
}


/* check boolean argument */
LAU_API int lau_checkboolean( lua_State *L, int idx )
{
    luaL_checktype( L, idx, LUA_TBOOLEAN );
    return lua_toboolean( L, idx );
}

LAU_API int lau_optboolean( lua_State *L, int idx, int def )
{
    if( lua_isnoneornil( L, idx ) ){
        return def > 0;
    }

    return lau_checkboolean( L, idx );
}


/* check bit flag arguments */
LAU_API int lau_optflags( lua_State *L, int idx )
{
    const int argc = lua_gettop( L );
    int flg = 0;
    
    for(; idx <= argc; idx++ ){
        flg |= (int)lau_optinteger( L, idx, 0 );
    }
    
    return flg;
}



// module definition register
LAU_API int lau_define_mt( lua_State *L, const char *tname,
                           struct luaL_Reg mmethod[],
                           struct luaL_Reg method[] )
{
    struct luaL_Reg *ptr = mmethod;
    
    // create table __metatable
    luaL_newmetatable( L, tname );
    // metamethods
    while( ptr->name ){
        lau_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }
    
    // methods
    ptr = method;
    lua_pushstring( L, "__index" );
    lua_newtable( L );
    while( ptr->name ){
        lau_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }
    lua_rawset( L, -3 );
    lua_pop( L, 1 );

    return 1;
}


#endif

