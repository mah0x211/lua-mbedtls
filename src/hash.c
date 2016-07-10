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
 *  src/hash.c
 *  lua-mbedtls
 *  Created by Masatoshi Teruya on 16/02/06.
 */


#include "lmbedtls.h"


static int finish_lua( lua_State *L )
{
    mbedtls_md_context_t *md = lauxh_checkudata( L, 1, LMBEDTLS_HASH_MT );
    unsigned char output[64] = { 0 };
    const char *ptr = (const char*)output;
    int rc = 0;

    if( md->hmac_ctx ){
        rc = mbedtls_md_hmac_finish( md, output );
        mbedtls_md_hmac_reset( md );
    }
    else {
        rc = mbedtls_md_finish( md, output );
        mbedtls_md_starts( md );
    }

    if( rc ){
        lmbedtls_errbuf_t errbuf;

        lmbedtls_strerror( rc, errbuf );
        lua_pushnil( L );
        lua_pushstring( L, errbuf );
        return 2;
    }

    switch( mbedtls_md_get_type( md->md_info ) ){
        case MBEDTLS_MD_MD2:
        case MBEDTLS_MD_MD4:
        case MBEDTLS_MD_MD5:
            lua_pushlstring( L, ptr, 16 );
            return 1;

        case MBEDTLS_MD_SHA1:
            lua_pushlstring( L, ptr, 20 );
            return 1;

        case MBEDTLS_MD_SHA224:
            lua_pushlstring( L, ptr, 28 );
            return 1;

        case MBEDTLS_MD_SHA256:
            lua_pushlstring( L, ptr, 32 );
            return 1;

        case MBEDTLS_MD_SHA384:
            lua_pushlstring( L, ptr, 48 );
            return 1;

        case MBEDTLS_MD_SHA512:
            lua_pushlstring( L, ptr, 64 );
            return 1;

        case MBEDTLS_MD_RIPEMD160:
            lua_pushlstring( L, ptr, 20 );
            return 1;

        default:
            return luaL_error( L, "%s - unknown md type configured",
                               strerror( EINVAL ) );
    }
}


static int update_lua( lua_State *L )
{
    mbedtls_md_context_t *md = lauxh_checkudata( L, 1, LMBEDTLS_HASH_MT );
    size_t len = 0;
    const char *key = lauxh_checklstring( L, 2, &len );
    int rc = 0;

    if( md->hmac_ctx ){
        rc = mbedtls_md_hmac_update( md, (const unsigned char*)key, len );
    }
    else {
        rc = mbedtls_md_update( md, (const unsigned char*)key, len );
    }

    if( rc ){
        lmbedtls_errbuf_t errbuf;

        lmbedtls_strerror( rc, errbuf );
        lua_pushboolean( L, 0 );
        lua_pushstring( L, errbuf );
        return 2;
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int tostring_lua( lua_State *L )
{
    return TOSTRING_MT( L, LMBEDTLS_HASH_MT );
}


static int gc_lua( lua_State *L )
{
    mbedtls_md_context_t *md = lua_touserdata( L, 1 );

    mbedtls_md_free( md );

    return 0;
}


static int new_lua( lua_State *L )
{
    const mbedtls_md_type_t type = lauxh_checkinteger( L, 1 );
    size_t len = 0;
    const char *key = lauxh_optlstring( L, 2, NULL, &len );
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type( type );
    mbedtls_md_context_t *md = NULL;
    int rc = 0;

    // unknown type
    if( !info ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( EINVAL ) );
        return 2;
    }
    // alloc error
    else if( !( md = lua_newuserdata( L, sizeof( mbedtls_md_context_t ) ) ) ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) ) ;
        return 2;
    }

    mbedtls_md_init( md );
    rc = mbedtls_md_setup( md, info, len );
    if( !rc ){
        rc = ( len ) ?
             mbedtls_md_hmac_starts( md, (const unsigned char*)key, len ) :
             mbedtls_md_starts( md );
    }
    // got error
    if( rc ){
        lmbedtls_errbuf_t errbuf;

        mbedtls_md_free( md );
        lmbedtls_strerror( rc, errbuf );
        lua_pushnil( L );
        lua_pushstring( L, errbuf );
        return 2;
    }

    lauxh_setmetatable( L, LMBEDTLS_HASH_MT );

    return 1;
}


#define hash_lua( L, hash_type, hash_api, digest, dlen, ... ) do{ \
    size_t ilen = 0; \
    const char *input = lauxh_checklstring( (L), 1, &ilen ); \
    /* check arguments */ \
    if( lua_isnoneornil( (L), 2 ) ){ \
        hash_api( (const unsigned char*)input, ilen, (digest), ##__VA_ARGS__ ); \
        lua_pushlstring( (L), (const char*)(digest), (dlen) ); \
        return 1; \
    } \
    else { \
        size_t klen = 0; \
        unsigned char *key = (unsigned char*)lauxh_checklstring( L, 2, &klen ); \
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type( hash_type ); \
        if( mbedtls_md_hmac( info, key, klen, (const unsigned char*)input, \
                             ilen, (digest) ) == 0 ){ \
            lua_pushlstring( (L), (const char*)(digest), (dlen) ); \
            return 1; \
        } \
    } \
    /* got error */ \
    lua_pushnil( (L) ); \
    lua_pushstring( (L), strerror( errno ) ); \
    return 2; \
}while(0)


static int ripemd160_lua( lua_State *L )
{
    unsigned char digest[20] = { 0 };
    hash_lua( L, MBEDTLS_MD_RIPEMD160, mbedtls_ripemd160, digest, 20 );
}


static int sha512_lua( lua_State *L )
{
    unsigned char digest[64] = { 0 };
    hash_lua( L, MBEDTLS_MD_SHA512, mbedtls_sha512, digest, 64, 0 );
}

static int sha384_lua( lua_State *L )
{
    unsigned char digest[64] = { 0 };
    hash_lua( L, MBEDTLS_MD_SHA384, mbedtls_sha512, digest, 48, 1 );
}

static int sha256_lua( lua_State *L )
{
    unsigned char digest[32] = { 0 };
    hash_lua( L, MBEDTLS_MD_SHA256, mbedtls_sha256, digest, 32, 0 );
}

static int sha224_lua( lua_State *L )
{
    unsigned char digest[32] = { 0 };
    hash_lua( L, MBEDTLS_MD_SHA224, mbedtls_sha256, digest, 28, 1 );
}

static int sha1_lua( lua_State *L )
{
    unsigned char digest[20] = { 0 };
    hash_lua( L, MBEDTLS_MD_SHA1, mbedtls_sha1, digest, 20 );
}

static int md5_lua( lua_State *L )
{
    unsigned char digest[16] = { 0 };
    hash_lua( L, MBEDTLS_MD_MD5, mbedtls_md5, digest, 16 );
}


LUALIB_API int luaopen_mbedtls_hash( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "update", update_lua },
        { "finish", finish_lua },
        { NULL, NULL }
    };
    struct luaL_Reg funcs[] = {
        { "md5", md5_lua },
        { "sha1", sha1_lua },
        { "sha224", sha224_lua },
        { "sha256", sha256_lua },
        { "sha384", sha384_lua },
        { "sha512", sha512_lua },
        { "ripemd160", ripemd160_lua },
        { "new", new_lua },
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = funcs;

    // register metatable
    lmbedtls_newmetatable( L, LMBEDTLS_HASH_MT, mmethod, method );

    // create table
    lua_newtable( L );
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }

    // add mbedtls_md_type_t
    lauxh_pushint2tbl( L, "MD2", MBEDTLS_MD_MD2 );
    lauxh_pushint2tbl( L, "MD4", MBEDTLS_MD_MD4 );
    lauxh_pushint2tbl( L, "MD5", MBEDTLS_MD_MD5 );
    lauxh_pushint2tbl( L, "SHA1", MBEDTLS_MD_SHA1 );
    lauxh_pushint2tbl( L, "SHA224", MBEDTLS_MD_SHA224 );
    lauxh_pushint2tbl( L, "SHA256", MBEDTLS_MD_SHA256 );
    lauxh_pushint2tbl( L, "SHA384", MBEDTLS_MD_SHA384 );
    lauxh_pushint2tbl( L, "SHA512", MBEDTLS_MD_SHA512 );
    lauxh_pushint2tbl( L, "RIPEMD160", MBEDTLS_MD_RIPEMD160 );

    return 1;
}

