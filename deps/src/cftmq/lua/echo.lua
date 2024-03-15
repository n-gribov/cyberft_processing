require('luastomp')

con=stomp.connect('127.0.0.1:40090')

if con then

    if con:login('root','') and con:subscribe('INPUT') then

        while true do
            local msg=con:recv()

            if not msg then break end

            print(msg.data)

            if tonumber(msg.timeout)>tonumber(os.time()) then
                con:send( { data=msg.data, destination=msg['reply-to'], status=200 } )
            else
                print('timeout expired')
            end

            con:ack()
        end

    end

end