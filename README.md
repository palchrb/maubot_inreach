# maubot_inreach
Something you did not know you need, and most likely you don't... Maubot plugin to enable you to chat with users of Garmin Inreach devices via your favorite matrix client :-) Can also be used to bridge matrix group chats to an inreach device (which could become expensive of course)


Its not beautiful code, and not very advanced and it's currently based on the fact that a (non-pro account) inreach can only send either text or emails.. So this is a combination of other projects of mine; the matrix room specific webhook plugin and my gmail to webhook plugin (and apps script) pub/sub push based instance. 

The way it works;
- !inreach sub alias to set up the system and generate a gmail + address that your inreach user can send their messages to
- The inreach user then needs to send the first message, to give the matrix room the right link to be able to respond via garmin api. Then everything is setup!
- The bridge will rotate reply links after each received message to make sure there is a fresh one available (and they don't seem to expire very quickly either.
- Check !inreach help for all commands in the room; but you can choose whether to bride only messages with !inreach send <message> or to send all user messages without any ! prefix commands (passive mode). You can also enable relay mode to relay all messages from multiple matrix users in the room.
- Currently only set up to bridge 1 room to 1 inreach user


Feel free to contact me [on Matrix](https://matrix.to/#/#whatever:vibb.me)
