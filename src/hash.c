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


#define digest2hex_lua( L, digest, len ) do{ \
    unsigned char hex[len * 2] = { 0 }; \
    hex_encode( hex, (digest), sizeof( (digest) ) ); \
    lua_pushlstring( (L), (const char*)hex, sizeof( hex ) ); \
}while(0)


#define hash_lua( L, hash_type, hash_api, digest, dlen, ... ) do{ \
    size_t ilen = 0; \
    const char *input = lauxh_checklstring( (L), 1, &ilen ); \
    /* check arguments */ \
    if( lua_isnoneornil( (L), 2 ) ){ \
        hash_api( (const unsigned char*)input, ilen, (digest), ##__VA_ARGS__ ); \
        digest2hex_lua( (L), (digest), (dlen) ); \
        return 1; \
    } \
    else { \
        size_t klen = 0; \
        unsigned char *key = (unsigned char*)lauxh_checklstring( L, 2, &klen ); \
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type( hash_type ); \
        if( mbedtls_md_hmac( info, key, klen, (const unsigned char*)input, \
                             ilen, (digest) ) == 0 ){ \
            digest2hex_lua( (L), (digest), (dlen) ); \
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
    struct luaL_Reg funcs[] = {
        { "md5", md5_lua },
        { "sha1", sha1_lua },
        { "sha224", sha224_lua },
        { "sha256", sha256_lua },
        { "sha384", sha384_lua },
        { "sha512", sha512_lua },
        { "ripemd160", ripemd160_lua},
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = funcs;

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

