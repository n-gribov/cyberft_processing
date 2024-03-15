require('luastomp')

con=stomp.connect('127.0.0.1:40090')

if con then

    if con:login('root','') and con:subscribe('test') then

        while true do
            local msg=con:recv()

            if not msg then break end

            print(msg.destination,msg.data)

            con:ack()
        end

    end

end