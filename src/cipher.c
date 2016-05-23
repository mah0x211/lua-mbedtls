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
 *  src/cipher.c
 *  lua-mbedtls
 *  Created by Masatoshi Teruya on 16/05/21.
 */


#include "lmbedtls.h"


static int checktag_lua( lua_State *L )
{
    lmbedtls_errbuf_t errbuf;
#if defined(MBEDTLS_GCM_C)
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    const char *tag = lauxh_checklstring( L, 2, &len );
    int rc = mbedtls_cipher_check_tag( ctx, (unsigned char*)tag, len );

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

#else
    int rc = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

#endif

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int writetag_lua( lua_State *L )
{
    lmbedtls_errbuf_t errbuf;
#if defined(MBEDTLS_GCM_C)
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    const char *tag = lauxh_checklstring( L, 2, &len );
    int rc = mbedtls_cipher_write_tag( ctx, (unsigned char*)tag, len );

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

#else
    int rc = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

#endif

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int finish_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    unsigned char output[BUFSIZ] = {0};
    int rc = mbedtls_cipher_finish( ctx, output, &len );
    lmbedtls_errbuf_t errbuf;

    if( rc == 0 ){
        lua_pushlstring( L, (const char*)output, len );
        return 1;
    }

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushnil( L );
    lua_pushstring( L, errbuf );

    return 2;
}


static int update_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    const char *data = lauxh_checklstring( L, 2, &len );
    const unsigned char *ptr = (const unsigned char*)data;
    size_t blksize = mbedtls_cipher_get_block_size( ctx );
    size_t tail = len % blksize;
    size_t last = len - tail;
    size_t offset = 0;
    size_t olen = 0;
    unsigned char output[BUFSIZ] = {0};
    int rc = 0;
    lmbedtls_errbuf_t errbuf;

    lua_settop( L, 0 );
    for(; offset < last; offset += blksize )
    {
        rc = mbedtls_cipher_update( ctx, ptr + offset, blksize, output, &olen );
        if( rc != 0 ){
            goto FAILED;
        }
        lua_pushlstring( L, (const char*)output, olen );
    }

    if( tail )
    {
        rc = mbedtls_cipher_update( ctx, ptr + offset, tail, output, &olen );
        if( rc == 0 ){
            lua_pushlstring( L, (const char*)output, olen );
        }
    }

    if( rc == 0 ){
        lua_concat( L, lua_gettop( L ) );
        return 1;
    }

FAILED:
    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_settop( L, 0 );
    lua_pushnil( L );
    lua_pushstring( L, errbuf );

    return 2;
}


static int updatead_lua( lua_State *L )
{
    lmbedtls_errbuf_t errbuf;
#if defined(MBEDTLS_GCM_C)
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    const char *data = lauxh_checklstring( L, 2, &len );
    int rc = mbedtls_cipher_update_ad( ctx, (const unsigned char*)data, len );

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

#else
    int rc = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

#endif

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int reset_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    int rc = mbedtls_cipher_reset( ctx );
    lmbedtls_errbuf_t errbuf;

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int setiv_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    const char *iv = lauxh_checklstring( L, 2, &len );
    int rc = mbedtls_cipher_set_iv( ctx, (const unsigned char*)iv, len );
    lmbedtls_errbuf_t errbuf;

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int setpaddingmode_lua( lua_State *L )
{
    lmbedtls_errbuf_t errbuf;
#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    mbedtls_cipher_padding_t pad = lauxh_checkinteger( L, 2 );
    int rc = mbedtls_cipher_set_padding_mode( ctx, pad );

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

#else
    int rc = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

#endif

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int setkey_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    size_t len = 0;
    const char *key = lauxh_checklstring( L, 2, &len );
    const mbedtls_operation_t op = lauxh_checkinteger( L, 3 );
    int rc = mbedtls_cipher_setkey( ctx, (const unsigned char*)key,
                                   (int)len * CHAR_BIT, op );
    lmbedtls_errbuf_t errbuf;

    if( rc == 0 ){
        lua_pushboolean( L, 1 );
        return 1;
    }

    // got error
    lmbedtls_strerror( rc, errbuf );
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errbuf );

    return 2;
}


static int getoperation_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );

    lua_pushinteger( L, mbedtls_cipher_get_operation( ctx ) );

    return 1;
}


static int getkeybitlen_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );

    lua_pushinteger( L, mbedtls_cipher_get_key_bitlen( ctx ) );

    return 1;
}


static int getname_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    const char *name = mbedtls_cipher_get_name( ctx );

    if( name ){
        lua_pushstring( L, name );
    }
    else {
        lua_pushnil( L );
    }

    return 1;
}


static int gettype_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );

    lua_pushinteger( L, mbedtls_cipher_get_type( ctx ) );

    return 1;
}


static int getivsize_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );

    lua_pushinteger( L, mbedtls_cipher_get_iv_size( ctx ) );

    return 1;
}


static int getciphermode_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );

    lua_pushinteger( L, mbedtls_cipher_get_cipher_mode( ctx ) );

    return 1;
}


static int getblocksize_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );

    lua_pushinteger( L, mbedtls_cipher_get_block_size( ctx ) );

    return 1;
}


static int init_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lauxh_checkudata( L, 1, LMBEDTLS_CIPHER_MT );
    const mbedtls_cipher_type_t type = lauxh_optinteger( L, 2, MBEDTLS_CIPHER_NONE );
    const mbedtls_cipher_info_t *info = NULL;
    int rc = 0;
    lmbedtls_errbuf_t errstr;

    // use current cipher info
    if( type == MBEDTLS_CIPHER_NONE ){
        info = ctx->cipher_info;
    }
    // check argument
    else if( !( info = mbedtls_cipher_info_from_type( type ) ) ){
        lua_pushboolean( L, 0 );
        lua_pushstring( L, strerror( EINVAL ) );
        return 2;
    }

    mbedtls_cipher_free( ctx );
    rc = mbedtls_cipher_setup( ctx, info );
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


static int tostring_lua( lua_State *L )
{
    return TOSTRING_MT( L, LMBEDTLS_CIPHER_MT );
}


static int gc_lua( lua_State *L )
{
    mbedtls_cipher_context_t *ctx = lua_touserdata( L, 1 );

    mbedtls_cipher_free( ctx );

    return 0;
}


static int new_lua( lua_State *L )
{
    const mbedtls_cipher_type_t type = lauxh_checkinteger( L, 1 );
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type( type );
    mbedtls_cipher_context_t *ctx = NULL;
    int rc = 0;

    if( !info ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( EINVAL ) );
        return 2;
    }

    ctx = lua_newuserdata( L, sizeof( mbedtls_cipher_context_t ) );
    if( !ctx ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    mbedtls_cipher_init( ctx );
    if( ( rc = mbedtls_cipher_setup( ctx, info ) ) != 0 ){
        lmbedtls_errbuf_t errstr;

        lmbedtls_strerror( rc, errstr );
        lua_pushnil( L );
        lua_pushstring( L, errstr );

        return 2;
    }

    lauxh_setmetatable( L, LMBEDTLS_CIPHER_MT );

    return 1;
}


LUALIB_API int luaopen_mbedtls_cipher( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "init", init_lua },
        { "getblocksize", getblocksize_lua },
        { "getciphermode", getciphermode_lua },
        { "getivsize", getivsize_lua },
        { "gettype", gettype_lua },
        { "getname", getname_lua },
        { "getkeybitlen", getkeybitlen_lua },
        { "getoperation", getoperation_lua },
        { "setkey", setkey_lua },
        { "setpaddingmode", setpaddingmode_lua },
        { "setiv", setiv_lua },
        { "reset", reset_lua },
        { "updatead", updatead_lua },
        { "update", update_lua },
        { "finish", finish_lua },
        { "writetag", writetag_lua },
        { "checktag", checktag_lua },
        /*
        { "crypt", crypt_lua },
        { "authcrypt", authcrypt_lua },
        { "authdecrypt", authdecrypt_lua },
        //*/
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = mmethod;

    // register metatable
    luaL_newmetatable( L, LMBEDTLS_CIPHER_MT );
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }
    // create table
    lua_pushstring( L, "__index" );
    lua_newtable( L );
    ptr = method;
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }
    lua_rawset( L, -3 );
    lua_pop( L, 1 );

    // create table
    lua_newtable( L );
    // add new function
    lauxh_pushfn2tbl( L, "new", new_lua );

    // add mbedtls_cipher_type_t
    lauxh_pushint2tbl( L, "AES_128_ECB", MBEDTLS_CIPHER_AES_128_ECB );
    lauxh_pushint2tbl( L, "AES_192_ECB", MBEDTLS_CIPHER_AES_192_ECB );
    lauxh_pushint2tbl( L, "AES_256_ECB", MBEDTLS_CIPHER_AES_256_ECB );
    lauxh_pushint2tbl( L, "AES_128_CBC", MBEDTLS_CIPHER_AES_128_CBC );
    lauxh_pushint2tbl( L, "AES_192_CBC", MBEDTLS_CIPHER_AES_192_CBC );
    lauxh_pushint2tbl( L, "AES_256_CBC", MBEDTLS_CIPHER_AES_256_CBC );
    lauxh_pushint2tbl( L, "AES_128_CFB128", MBEDTLS_CIPHER_AES_128_CFB128 );
    lauxh_pushint2tbl( L, "AES_192_CFB128", MBEDTLS_CIPHER_AES_192_CFB128 );
    lauxh_pushint2tbl( L, "AES_256_CFB128", MBEDTLS_CIPHER_AES_256_CFB128 );
    lauxh_pushint2tbl( L, "AES_128_CTR", MBEDTLS_CIPHER_AES_128_CTR );
    lauxh_pushint2tbl( L, "AES_192_CTR", MBEDTLS_CIPHER_AES_192_CTR );
    lauxh_pushint2tbl( L, "AES_256_CTR", MBEDTLS_CIPHER_AES_256_CTR );
    lauxh_pushint2tbl( L, "AES_128_GCM", MBEDTLS_CIPHER_AES_128_GCM );
    lauxh_pushint2tbl( L, "AES_192_GCM", MBEDTLS_CIPHER_AES_192_GCM );
    lauxh_pushint2tbl( L, "AES_256_GCM", MBEDTLS_CIPHER_AES_256_GCM );
    lauxh_pushint2tbl( L, "CAMELLIA_128_ECB", MBEDTLS_CIPHER_CAMELLIA_128_ECB );
    lauxh_pushint2tbl( L, "CAMELLIA_192_ECB", MBEDTLS_CIPHER_CAMELLIA_192_ECB );
    lauxh_pushint2tbl( L, "CAMELLIA_256_ECB", MBEDTLS_CIPHER_CAMELLIA_256_ECB );
    lauxh_pushint2tbl( L, "CAMELLIA_128_CBC", MBEDTLS_CIPHER_CAMELLIA_128_CBC );
    lauxh_pushint2tbl( L, "CAMELLIA_192_CBC", MBEDTLS_CIPHER_CAMELLIA_192_CBC );
    lauxh_pushint2tbl( L, "CAMELLIA_256_CBC", MBEDTLS_CIPHER_CAMELLIA_256_CBC );
    lauxh_pushint2tbl( L, "CAMELLIA_128_CFB128", MBEDTLS_CIPHER_CAMELLIA_128_CFB128 );
    lauxh_pushint2tbl( L, "CAMELLIA_192_CFB128", MBEDTLS_CIPHER_CAMELLIA_192_CFB128 );
    lauxh_pushint2tbl( L, "CAMELLIA_256_CFB128", MBEDTLS_CIPHER_CAMELLIA_256_CFB128 );
    lauxh_pushint2tbl( L, "CAMELLIA_128_CTR", MBEDTLS_CIPHER_CAMELLIA_128_CTR );
    lauxh_pushint2tbl( L, "CAMELLIA_192_CTR", MBEDTLS_CIPHER_CAMELLIA_192_CTR );
    lauxh_pushint2tbl( L, "CAMELLIA_256_CTR", MBEDTLS_CIPHER_CAMELLIA_256_CTR );
    lauxh_pushint2tbl( L, "CAMELLIA_128_GCM", MBEDTLS_CIPHER_CAMELLIA_128_GCM );
    lauxh_pushint2tbl( L, "CAMELLIA_192_GCM", MBEDTLS_CIPHER_CAMELLIA_192_GCM );
    lauxh_pushint2tbl( L, "CAMELLIA_256_GCM", MBEDTLS_CIPHER_CAMELLIA_256_GCM );
    lauxh_pushint2tbl( L, "DES_ECB", MBEDTLS_CIPHER_DES_ECB );
    lauxh_pushint2tbl( L, "DES_CBC", MBEDTLS_CIPHER_DES_CBC );
    lauxh_pushint2tbl( L, "DES_EDE_ECB", MBEDTLS_CIPHER_DES_EDE_ECB );
    lauxh_pushint2tbl( L, "DES_EDE_CBC", MBEDTLS_CIPHER_DES_EDE_CBC );
    lauxh_pushint2tbl( L, "DES_EDE3_ECB", MBEDTLS_CIPHER_DES_EDE3_ECB );
    lauxh_pushint2tbl( L, "DES_EDE3_CBC", MBEDTLS_CIPHER_DES_EDE3_CBC );
    lauxh_pushint2tbl( L, "BLOWFISH_ECB", MBEDTLS_CIPHER_BLOWFISH_ECB );
    lauxh_pushint2tbl( L, "BLOWFISH_CBC", MBEDTLS_CIPHER_BLOWFISH_CBC );
    lauxh_pushint2tbl( L, "BLOWFISH_CFB64", MBEDTLS_CIPHER_BLOWFISH_CFB64 );
    lauxh_pushint2tbl( L, "BLOWFISH_CTR", MBEDTLS_CIPHER_BLOWFISH_CTR );
    lauxh_pushint2tbl( L, "ARC4_128", MBEDTLS_CIPHER_ARC4_128 );
    lauxh_pushint2tbl( L, "AES_128_CCM", MBEDTLS_CIPHER_AES_128_CCM );
    lauxh_pushint2tbl( L, "AES_192_CCM", MBEDTLS_CIPHER_AES_192_CCM );
    lauxh_pushint2tbl( L, "AES_256_CCM", MBEDTLS_CIPHER_AES_256_CCM );
    lauxh_pushint2tbl( L, "CAMELLIA_128_CCM", MBEDTLS_CIPHER_CAMELLIA_128_CCM );
    lauxh_pushint2tbl( L, "CAMELLIA_192_CCM", MBEDTLS_CIPHER_CAMELLIA_192_CCM );
    lauxh_pushint2tbl( L, "CAMELLIA_256_CCM", MBEDTLS_CIPHER_CAMELLIA_256_CCM );

    // add mbedtls_cipher_mode_t
    lauxh_pushint2tbl( L, "MODE_NONE", MBEDTLS_MODE_NONE );
    lauxh_pushint2tbl( L, "MODE_ECB", MBEDTLS_MODE_ECB );
    lauxh_pushint2tbl( L, "MODE_CBC", MBEDTLS_MODE_CBC );
    lauxh_pushint2tbl( L, "MODE_CFB", MBEDTLS_MODE_CFB );
    lauxh_pushint2tbl( L, "MODE_CTR", MBEDTLS_MODE_CTR );
    lauxh_pushint2tbl( L, "MODE_GCM", MBEDTLS_MODE_GCM );
    lauxh_pushint2tbl( L, "MODE_STREAM", MBEDTLS_MODE_STREAM );
    lauxh_pushint2tbl( L, "MODE_CCM", MBEDTLS_MODE_CCM );

    // add mbedtls_cipher_padding_t
    lauxh_pushint2tbl( L, "PADDING_PKCS7", MBEDTLS_PADDING_PKCS7 );
    lauxh_pushint2tbl( L, "PADDING_ONE_AND_ZEROS", MBEDTLS_PADDING_ONE_AND_ZEROS );
    lauxh_pushint2tbl( L, "PADDING_ZEROS_AND_LEN", MBEDTLS_PADDING_ZEROS_AND_LEN );
    lauxh_pushint2tbl( L, "PADDING_ZEROS", MBEDTLS_PADDING_ZEROS );
    lauxh_pushint2tbl( L, "PADDING_NONE", MBEDTLS_PADDING_NONE );

    // add mbedtls_operation_t
    lauxh_pushint2tbl( L, "OP_NONE", MBEDTLS_OPERATION_NONE );
    lauxh_pushint2tbl( L, "OP_DECRYPT", MBEDTLS_DECRYPT );
    lauxh_pushint2tbl( L, "OP_ENCRYPT", MBEDTLS_ENCRYPT );

    return 1;
}

