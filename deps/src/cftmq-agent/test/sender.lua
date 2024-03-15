require('luastomp')

con=stomp.connect('127.0.0.1:40090')

if con then

    if con:login('root','') then

--        con:send( { data='hello', destination='test', ['seq-id']='1234', ['chunk-id']='1/2',
--            ['chunk-range']='0-4/10', ['chunk-dgst']='14e1a1785cc9716a6b8ff8161e394337' } )

        con:send( { data='world', destination='test', ['seq-id']='1234', ['chunk-id']='2/2',
            ['chunk-range']='5-9/10', ['chunk-dgst']='14e1a1785cc9716a6b8ff8161e394337' } )

    end

end