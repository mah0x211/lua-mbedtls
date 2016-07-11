local rng = require('mbedtls.rng')
local r = ifNil( rng.new( 'my seed' ) )

r:setresistance( true )
r:setresistance( false )
r:setentropylen( 48 )
r:setentropylen( 32 )
r:setreseedintvl( 10000 )
ifNotTrue( r:reseed( 'my seed update' ) )

local bin = ifNil( r:random() )
ifNotEqual( #bin, 1024 )
