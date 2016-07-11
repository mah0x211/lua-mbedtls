local unpack = unpack or table.unpack;
local hexencode = require('hex').encode;
local pk = require('mbedtls.pk')
local rng = require('mbedtls.rng')
local KEY = ifNil( rng.new( 'gen key' ) )
local FEATURE = {
    { alg = pk.EC, name = 'EC', bits = 256, key = KEY, gid = pk.BP256R1 },
    { alg = pk.EC, name = 'EC', bits = 384, key = KEY, gid = pk.BP384R1 },
    { alg = pk.EC, name = 'EC', bits = 512, key = KEY, gid = pk.BP512R1 },
    { alg = pk.EC, name = 'EC', bits = 255, key = KEY, gid = pk.CURVE25519 },
    { alg = pk.EC, name = 'EC', bits = 192, key = KEY, gid = pk.SECP192K1 },
    { alg = pk.EC, name = 'EC', bits = 192, key = KEY, gid = pk.SECP192R1 },
    { alg = pk.EC, name = 'EC', bits = 224, key = KEY, gid = pk.SECP224K1 },
    { alg = pk.EC, name = 'EC', bits = 224, key = KEY, gid = pk.SECP224R1 },
    { alg = pk.EC, name = 'EC', bits = 256, key = KEY, gid = pk.SECP256K1 },
    { alg = pk.EC, name = 'EC', bits = 256, key = KEY, gid = pk.SECP256R1 },
    { alg = pk.EC, name = 'EC', bits = 384, key = KEY, gid = pk.SECP384R1 },
    { alg = pk.EC, name = 'EC', bits = 521, key = KEY, gid = pk.SECP521R1 },
    { alg = pk.RSA, name = 'RSA', bits = 256, key = KEY },
};


local function write2file( pathname, val )
    local fh = ifNil( io.open( pathname, 'w+' ) );

    fh:write( val );
    fh:close();
end


for _, feature in ipairs( FEATURE ) do
    -- create new pk
    local p = ifNil( pk.new( feature.alg ) );
    local src = 'hello ' .. feature.name .. ' world!';
    local public = {};
    local private = {};
    local genkey, enc, dec;


    -- genkey
    if feature.alg == pk.RSA or feature.alg == pk.EC then
        -- genkey RSA
        if feature.alg == pk.RSA then
            ifNotTrue( p:genkey( feature.key, feature.bits ) );
        -- genkey EC
        elseif feature.alg == pk.EC then
            ifNotTrue( p:genkey( feature.key, feature.gid ) );
        end

        -- check properties
        ifNotEqual( feature.name, p:getname() );
        ifNotEqual( feature.alg, p:gettype() );
        ifNotEqual( feature.bits, p:getbitlen() );

        -- writekey
        if feature.alg == pk.RSA or
          feature.alg == pk.EC and feature.gid ~= pk.CURVE25519 then
            -- create der-encoded key
            write2file( './private.der', ifNil( p:writekeyder() ) );
            write2file( './public.der', ifNil( p:writepubkeyder() ) );
            -- create pem-encoded key
            write2file( './private.pem', p:writekeypem() );
            write2file( './public.pem', p:writepubkeypem() );
        end
    end

    -- crypt
    if feature.alg == pk.RSA then
        -- encrypt
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name ) );
        ifNotEqual( src, p:decrypt( enc, genkey ) );


        -- crypt by private pem
        p = ifNil( pk.parsekeyfile( './private.pem' ) );
        -- encrypt
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name .. ' by private pem' ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by private pem' ) );
        ifNotEqual( src, p:decrypt( enc, genkey ) );


        -- encrypt by public pem
        p = ifNil( pk.parsepubkeyfile( './public.pem' ) );
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name .. ' by public pem' ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt by public pem
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by public pem' ) );
        ifNotNil( p:decrypt( enc, genkey ) );
        -- decrypt by private pem
        p = ifNil( pk.parsekeyfile( './private.pem' ) );
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by private pem' ) );
        ifNotEqual( src, p:decrypt( enc, genkey ) );


        -- encrypt by private pem
        p = ifNil( pk.parsekeyfile( './private.pem' ) );
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name .. ' by private pem' ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt by public pem
        p = ifNil( pk.parsepubkeyfile( './public.pem' ) );
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by public pem' ) );
        ifNotNil( p:decrypt( enc, genkey ) );


        -- crypt by private der
        p = ifNil( pk.parsekeyfile( './private.der' ) );
        -- encrypt
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name .. ' by private der' ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by private der' ) );
        ifNotEqual( src, p:decrypt( enc, genkey ) );


        -- encrypt by public der
        p = ifNil( pk.parsepubkeyfile( './public.der' ) );
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name .. ' by public der' ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt by public der
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by public der' ) );
        ifNotNil( p:decrypt( enc, genkey ) );
        -- decrypt by private der
        p = ifNil( pk.parsekeyfile( './private.der' ) );
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by private der' ) );
        ifNotEqual( src, p:decrypt( enc, genkey ) );


        -- encrypt by private der
        p = ifNil( pk.parsekeyfile( './private.der' ) );
        genkey = ifNil( rng.new( 'encrypt ' .. feature.name .. ' by private der' ) );
        enc = ifNil( p:encrypt( src, genkey ) );
        -- decrypt by public der
        p = ifNil( pk.parsepubkeyfile( './public.der' ) );
        genkey = ifNil( rng.new( 'decrypt ' .. feature.name  .. ' by public der' ) );
        ifNotNil( p:decrypt( enc, genkey ) );
    end
end

