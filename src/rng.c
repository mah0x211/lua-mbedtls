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
 *  src/rng.c
 *  lua-mbedtls
 *  Created by Masatoshi Teruya on 16/05/22.
 */


#include "lmbedtls.h"


static int random_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lauxh_checkudata( L, 1, LMBEDTLS_RNG_MT );
    size_t len = lauxh_optinteger( L, 2, MBEDTLS_CTR_DRBG_MAX_REQUEST );
    unsigned char output[MBEDTLS_CTR_DRBG_MAX_REQUEST] = {0};
    int rc = mbedtls_ctr_drbg_random( &rng->drbg, output, len );
    lmbedtls_errbuf_t errstr;

    if( rc == 0 ){
        lua_pushlstring( L, (const char*)output, len );
        return 1;
    }

    // got error
    lmbedtls_strerror( rc, errstr );
    lua_pushnil( L );
    lua_pushstring( L, errstr );

    return 2;
}


static int update_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lauxh_checkudata( L, 1, LMBEDTLS_RNG_MT );
    size_t len = 0;
    const char *seed = lauxh_checklstring( L, 2, &len );

    mbedtls_ctr_drbg_update( &rng->drbg, (const unsigned char*)seed, len );

    return 0;
}


static int reseed_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lauxh_checkudata( L, 1, LMBEDTLS_RNG_MT );
    size_t len = 0;
    const char *seed = lauxh_checklstring( L, 2, &len );
    int rc = mbedtls_ctr_drbg_reseed( &rng->drbg, (const unsigned char*)seed,
                                      len );
    lmbedtls_errbuf_t errstr;

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

    // got error
    lmbedtls_strerror( rc, errstr );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errstr );

    return 2;
}


static int setreseedintvl_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lauxh_checkudata( L, 1, LMBEDTLS_RNG_MT );
    int itvl = lauxh_checkinteger( L, 2 );

    mbedtls_ctr_drbg_set_reseed_interval( &rng->drbg, itvl );

    return 0;
}


static int setentropylen_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lauxh_checkudata( L, 1, LMBEDTLS_RNG_MT );
    int len = lauxh_checkinteger( L, 2 );

    mbedtls_ctr_drbg_set_entropy_len( &rng->drbg, len );

    return 0;
}


static int setresistance_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lauxh_checkudata( L, 1, LMBEDTLS_RNG_MT );
    int resistance = lauxh_checkboolean( L, 2 );

    mbedtls_ctr_drbg_set_prediction_resistance( &rng->drbg, resistance );

    return 0;
}


static int tostring_lua( lua_State *L )
{
    return TOSTRING_MT( L, LMBEDTLS_RNG_MT );
}


static int gc_lua( lua_State *L )
{
    lmbedtls_rng_t *rng = lua_touserdata( L, 1 );

    mbedtls_ctr_drbg_free( &rng->drbg );
    mbedtls_entropy_free( &rng->entropy );

    return 0;
}


static int new_lua( lua_State *L )
{
    size_t len = 0;
    const char *seed = lauxh_optlstring( L, 1, NULL, &len );
    lmbedtls_rng_t *rng = lua_newuserdata( L, sizeof( lmbedtls_rng_t ) );
    int rc = 0;
    lmbedtls_errbuf_t errstr;

    if( !rng ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    mbedtls_ctr_drbg_init( &rng->drbg );
    mbedtls_entropy_init( &rng->entropy );
    rc = mbedtls_ctr_drbg_seed( &rng->drbg, mbedtls_entropy_func, &rng->entropy,
                               (const unsigned char*)seed, len );

    if( rc == 0 ){
        lauxh_setmetatable( L, LMBEDTLS_RNG_MT );
        return 1;
    }

    // got error
    mbedtls_ctr_drbg_free( &rng->drbg );
    mbedtls_entropy_free( &rng->entropy );
    lmbedtls_strerror( rc, errstr );
    lua_pushnil( L );
    lua_pushstring( L, errstr );

    return 2;
}


LUALIB_API int luaopen_mbedtls_rng( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "setresistance", setresistance_lua },
        { "setentropylen", setentropylen_lua },
        { "setreseedintvl", setreseedintvl_lua },
        { "reseed", reseed_lua },
        { "update", update_lua },
        //{ "randomwadd", randomwadd_lua },
        { "random", random_lua },
        //{ "writeseedfile", writeseedfile_lua },
        //{ "updateseedfile", updateseedfile_lua },
        { NULL, NULL }
    };

    // register metatable
    lmbedtls_newmetatable( L, LMBEDTLS_RNG_MT, mmethod, method );

    // create table
    lua_newtable( L );
    // add new function
    lauxh_pushfn2tbl( L, "new", new_lua );


    return 1;
}

