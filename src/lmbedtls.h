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
 *  src/lmbedtls.h
 *  lua-mbedtls
 *  Created by Masatoshi Teruya on 16/02/06.
 */


#ifndef mbedtls_lua_h
#define mbedtls_lua_h

#include <string.h>
#include <errno.h>
// lualib
#include "config.h"
// utilities
#include "hexcodec.h"
#include "lauxhlib.h"
// mbedtls headers
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/cipher.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crl.h"


#define TOSTRING_MT(L,tname) ({ \
    lua_pushfstring( L, tname ": %p", lua_touserdata( L, 1 ) ); \
    1; \
})


// helper functions

typedef char lmbedtls_errbuf_t[BUFSIZ];

static inline void lmbedtls_strerror( int rc, lmbedtls_errbuf_t errbuf )
{
    mbedtls_strerror( rc, errbuf, BUFSIZ );
}

static inline void lmbedtls_newmetatable( lua_State *L, const char *tname,
                                          struct luaL_Reg mm[], luaL_Reg m[] )
{
    struct luaL_Reg *ptr = mm;

    // register metatable
    luaL_newmetatable( L, tname );
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }
    // push methods into __index table
    lua_pushstring( L, "__index" );
    lua_newtable( L );
    ptr = m;
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }
    lua_rawset( L, -3 );
    lua_pop( L, 1 );
}


// define module names
#define LMBEDTLS_MD_MT          "mbedtls.md"
#define LMBEDTLS_RNG_MT         "mbedtls.rng"
#define LMBEDTLS_CIPHER_MT      "mbedtls.cipher"
#define LMBEDTLS_PK_MT          "mbedtls.pk"
#define LMBEDTLS_X509_CRL_MT    "mbedtls.x509.crl"


// define data types

typedef struct {
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
} lmbedtls_rng_t;


// define prototypes
LUALIB_API int luaopen_mbedtls_md( lua_State *L );
LUALIB_API int luaopen_mbedtls_rng( lua_State *L );
LUALIB_API int luaopen_mbedtls_cipher( lua_State *L );
LUALIB_API int luaopen_mbedtls_pk( lua_State *L );
LUALIB_API int luaopen_mbedtls_x509_crl( lua_State *L );


#endif

