require('luastomp')

con=stomp.connect('127.0.0.1:40090')

if con then

    if con:login('admin','') then

        con:send( { command='SYSTEM', cmd='size', arg='INPUT,OUTPUT,test' } )

        local receipt=con:recv()

        if receipt and receipt.command=='SYSTEM' then
            print(receipt.data)
        end

    end

end
