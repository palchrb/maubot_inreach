# maubot_inreach
Something you did not know you need, and most likely you don't... Maubot plugin to enable you to chat with users of Garmin Inreach devices via your favorite matrix client :-) Can also be used to bridge matrix group chats to an inreach device (which could become expensive of course)


Its not beautiful code, and not very advanced and it's currently based on the fact that a (non-pro account) inreach can only send either text or emails.. So this is a combination of other projects of mine; the matrix room specific webhook plugin and my gmail to webhook plugin (and apps script) pub/sub push based instance. This means in its current form you need to have setup a gmail address and and a connect apps script to manage incoming emails from the inreach user and bridge them to the matrix room via webhook, the code from here is copy paste to use for this exact purpose: (https://github.com/palchrb/gmail_webhook/). In addition you either need to set up a timer every few minutes or so to trigger the script - or as i have done, set up a google cloud project to get pub/sub set up where incoming emails trigger that the script instantly runs. It could probably be done in a nicer way if you have a inreach pro subscription with access to garmin's api for inreach - but i don't so then i made the poor man's version of it.

The way it works;
- !inreach sub alias to set up the system and generate a gmail + address that your inreach user can send their messages to
- The inreach user then needs to send the first message, to give the matrix room the right link to be able to respond via garmin api. Then everything is setup!
- The bridge will rotate reply links after each received message to make sure there is a fresh one available (and they don't seem to expire very quickly either.
- Check !inreach help for all commands in the room; but you can choose whether to bride only messages with !inreach send <message> or to send all user messages without any ! prefix commands (passive mode). You can also enable relay mode to relay all messages from multiple matrix users in the room.
- Currently only set up to bridge 1 room to 1 inreach user (but supports multiple rooms of course)

Stuff i could consider changing;
- Maybe more elegant to use IMAP_CLIENT inside maubot? With IMAP IDLE it would be quite similar to pub/sub from gmail and people can choose their own IMAP account providers
- Does not support images og voice, as i only have Inreach mini 2 which does not support this i have not seen the need yet
- Probably something else as well!

Also supports msc4144 proposal, so for compatible matrix clients you can see and set a display name and avatar for the bot user per message actually received from the inreach user.

Feel free to contact me [on Matrix](https://matrix.to/#/#whatever:vibb.me)
