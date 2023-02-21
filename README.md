# NoDoxx-Discord

This is a project in the making to help protect Discord-Client users' anonymity by filtering messages that may reveal personal details about them they do not wish to share.
When such information is found, the application suspends and closes the Discord Client.
This is suboptimal, but as long as the address that contains the single representation of the chat message that is not used for display/other purposes, but for storage, is found, there aren't many better options.<br>
<br>
You can configure 'forbidden strings' i.e. words (or phrases) in the file forbidden_strings.txt. This file has to be in the same directory as the application.<br>
When one such forbidden string is a substring of the chat message that the user is currently typing in the Discord Client, the aforementioned action of closing the Client is taken.
