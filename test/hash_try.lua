local hexencode = require('hex').encode;
local hash = require('mbedtls.hash');
local FEATURE = {
    {
        alg = 'md5',
        cmp = {
            '5d41402abc4b2a76b9719d911017c592',
            '76aa45638c98a95c14fe6d1a049ffece'
        }
    },
    {
        alg = 'ripemd160',
        cmp = {
            '108f07b8382412612c048d07d13f814118445acd',
            '23e200883a8ef34d5c9e619ecd35dd3bea256a6d'
        }
    },
    {
        alg = 'sha1',
        cmp = {
            'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
            '99ecf3db31397aa74159fe1dabb1a995d96f07c3'
        }
    },
    {
        alg = 'sha224',
        cmp = {
            'ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193',
            '877bb080d0ef44f60bcb8457f9bc8d505ded1b666f552efd44648553'
        }
    },
    {
        alg = 'sha256',
        cmp = {
            '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
            'da9ef9b9d92cae951d9ee92a997ef235bf47572681258bb27d80374d4a9855ec'
        }
    },
    {
        alg = 'sha384',
        cmp = {
            '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f',
            '5b2df2e2bc541c44eeb04af7a9bcb7d38ac2cab01246a61c9f171dc0507ac926b6c74aa4cec53c825ae0e4d69f645df2'
        }
    },
    {
        alg = 'sha512',
        cmp = {
            '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043',
            '8ec27b12f0867f59f8b34595850ab411d560f88fe1598220af5668b6877b70af3a5565570c5c59585abf461840989332ee489f0a42dc17d2a44a9461905a1e48'
        }
    }
};
local src = 'hello';
local key = 'hmac';
local h, err;

for _, feature in ipairs( FEATURE ) do
    ifNotEqual( feature.cmp[1], hexencode( hash[feature.alg]( src ) ) );
    ifNotEqual( feature.cmp[2], hexencode( hash[feature.alg]( src, key ) ) );

    -- hash
    h = ifNil( hash.new( hash[feature.alg:upper()] ) );
    ifNotTrue( h:update( src ) );
    ifNotEqual( feature.cmp[1], hexencode( h:finish() ) );
    -- reuse
    ifNotTrue( h:update( src ) );
    ifNotEqual( feature.cmp[1], hexencode( h:finish() ) );

    -- hmac-hash
    h = ifNil( hash.new( hash[feature.alg:upper()], key ) );
    ifNotTrue( h:update( src ) );
    ifNotEqual( feature.cmp[2], hexencode( h:finish() ) );
    -- reuse
    ifNotTrue( h:update( src ) );
    ifNotEqual( feature.cmp[2], hexencode( h:finish() ) );
end
