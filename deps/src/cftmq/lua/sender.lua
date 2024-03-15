require('luastomp')

con=stomp.connect('127.0.0.1:40090')

if con then

    if con:login('root','') then

        con:send( { data='hello', destination='test', receipt='123', ['max-num']=1000 } )

        local receipt=con:recv()

        if receipt and receipt.command=='RECEIPT' then
            print('OK',receipt['queue-size'],receipt['receipt-id'])
        end

    end

end