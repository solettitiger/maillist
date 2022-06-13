# maillist

If you need to send a newsletter to a lot of people with Outlook, a list of email addresses separated by a semicolon can be used in BCC as receipients.
To manage such lists of email addresses saved to textfiles you can use maillist. You can print all lists togehther or only one. You can search, filter the lists, verify the email addresses, search for double entries, add or delete items and move an email from one list to another. 


## Usage
```
 -s 		Search for an email address
 -f       	use only one list or use all lists (the filter is the filename without the extension)
 -a 		add an email address
 -d 		delete an email address
 -t double	searches for double entries, which you can remove
 -t verify	easy check if email address is valid (checks only the format)
 -m          	move an email address from one list to another
  		just show all email addresses
 -h		prints out short information on how to use maillist           
```

## Requirements
- Python 3 installed on your PC


## Installation
Copy all files into a folder on your computer. Edit config.ini to define the location of your files with the email addresses. Make the file `maillist` executable.


