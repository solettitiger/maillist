#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

# manages lists of email addresses stored in files
# configuration with an ini-file
#
# EBID/Bernd Scholler(bernd.scholler@ebid.at), June 2022
# License: GNU

from configparser import ConfigParser
from argparse import ArgumentParser
import os, enum, re


# ###################################################################
# CONFIG
# ###################################################################
curr_dir = os.getcwd()

# ###################################################################
# CLASSES, TYPES
# ###################################################################
class MailAdr:
	""" each Type of Mailaddresses is saved in one of these objects """
	def __init__(self, adr_type = '', adr_values = []):
		self.adr_type = adr_type
		self.adr_values = adr_values


class Func(enum.Enum):
	""" select from predefined values """
	double = "double"
	verify = "verify"

# ###################################################################
# HELPER FUNCTIONS
# ###################################################################
def get_mail_list_types(mail_lists):
	""" creates the Types of Mailaddresses from the filename """
	mail_list_types = []
	for mail_list in mail_lists:
		mail_list_types.append('.'.join(os.path.basename(mail_list).split('.')[:-1]))		
	return mail_list_types


def read_mail_list_file(filename):
	""" reads the Mailaddresses to a list """
	try:
		with open(filename, "r") as f:
			mails = [line.strip() for line in f]
		return list(filter(None, mails))
	except FileNotFoundError:
		print("")
		print(f"### ERROR:\nfile {filename} not found; check maillist.ini for proper configuration!")
		print("")
		os._exit(os.EX_OSFILE)
	

def print_mail_addresses(mails):
	""" prints content of the maillist files """
	for mail in mails:
		print(mail)
		
		
def filter_mail_list(mail_adrs, mail_list_filter = ""):
	""" prints content of maillists with filter. It will print only one file specified by the filter """
	for mail_adr in mail_adrs:
		if mail_adr.adr_type.lower() == mail_list_filter.lower(): # not case sensitive (would be to complicated to use)
			print_mail_addresses(mail_adr.adr_values)

			
def search_mail_list(adrs, srchstr = "", listname = "")->int:
	""" searches the provided list of email addresses for searchstring and prints them """
	srchstr = srchstr.lower()
	srchobj = filter(lambda adr: srchstr in adr.lower(), adrs) # search not case sensitive as mail addresses are
	mails = list(srchobj)
	for mail in mails:
		print(f"{listname}: {mail}")
	return len(mails)


def check_doubles(adrs, email):
	""" checks the provided list of email addresses for the entry defined in email. Returns true if email was found """
	email = email.lower()
	return True if(any(adr.lower() == email for adr in adrs)) else False


def check_is_in_list(adrs, email):
	""" checks if the email is in the list. Returns false if email was found """
	email = email.lower()
	return False if(any(adr.lower() == email for adr in adrs)) else True


def check_email_validity(email):
	""" very rudimentary check if email is valid """
	pattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
	valid = re.search(pattern, email)
	return True if valid else False


def check_line_validity(email):
	""" check if line consits of an email address and a semicolon at the end """
	if email[-1] != ";":
		return False
	if check_email_validity(email[:-1]) == False:
		return False
	return True


def remove_semicolon(email):
	""" deletes the Semicolon at the end of the line, if there is one. """
	return email[:-1] if(email[-1] == ";") else email


def del_from_list(adrs, email):
	""" deletes all items with email regardless of case """
	return [adr for adr in adrs if adr.lower() != email.lower()] # returns only that items, that are NOT equal, and so removes that one provided


def write_list_to_file(emails, filename):
	""" writes a list of emails to a file """
	try:
		with open(filename, "w") as f:
			for email in emails:
				print(email, file=f)
	except FileNotFoundError:
		print("")
		print(f"### ERROR:\nfile {filename} not found; check maillist.ini for proper configuration!")
		print("")
		os._exit(os.EX_OSFILE)
	

# ###################################################################
# FUNCTIONS
# ###################################################################
def read_config():
	"""
	reads ini-File for configuration
	
	:return: List of files with mail addresses as configured in ini-file
	:rtype: list:str
	"""
	config = ConfigParser(converters={'list': lambda x: [i.strip() for i in x.split(',')]})
	config.read('maillist.ini')
	mail_lists = config.has_option('DEFAULT','Mailfiles') and config.getlist('DEFAULT','Mailfiles') or None
	if mail_lists == None:
		print("")
		print("### ERROR:\nno mailing lists found; check maillist.ini for proper configuration!")
		print("")
		os._exit(os.EX_CONFIG)
	return mail_lists


def search_list(searchstring, searchfilter, mail_adrs)->None:
	""" 
	Searches the mail lists for part of a item 
	
	:param str searchstring: what to search for
	:param str searchfilter: optional search only in one file specified here
	:param list:MailAdr mail_adrs: address lists
	:return: Nothing
	:rtype: None	
	"""
	hasitems = 0
	if searchfilter != None:
		for mail_adr in mail_adrs:
			if mail_adr.adr_type.lower() == searchfilter.lower(): # not case sensitive (would be to complicated to use)
				hasitems += search_mail_list(mail_adr.adr_values, searchstring, mail_adr.adr_type)
				break
		if hasitems == 0:
			print("Nothing found\n")
		exit()
	else:
		for mail_adr in mail_adrs:
			hasitems += search_mail_list(mail_adr.adr_values, searchstring, mail_adr.adr_type)
		if hasitems == 0:
			print("Nothing found\n")
		exit()


def add_address(address, addfilter, mail_adrs, mail_lists)->None:
	""" 
	Add a new mail address to the list 
	
	:param str address: email address to add
	:param str addfilter: file to which we will add the address
	:param list:MailAdr mail_adrs: address lists
	:param list mail_lists: list of files
	:return: Nothing
	:rtype: None
	"""
	if addfilter == None:
		print("usage: maillist.py [-a ADDADDRESS] [-f FILTER]")
		print("       Use -f Parameter to specify to which file the new mailaddress should be added.\n")
		exit()
	else:
		new_mail_adr = remove_semicolon(address)  # in case of an added semicolon, it will be removed, because it is not an part of the email address
		if check_email_validity(new_mail_adr):                                    # is the mailaddress valid?
			for i, mail_adr in enumerate(mail_adrs):                              # search for the mail_list file
				if mail_adr.adr_type.lower() == addfilter.lower():
					new_mail_adr = new_mail_adr+";"                               # add semicolon
					if check_doubles(mail_adr.adr_values, new_mail_adr):          # check for double entries
						print(f"{new_mail_adr[:-1]} already found in {mail_lists[i]}. Email not added.\n")
						exit()
					mail_adr.adr_values.append(new_mail_adr)                      # add to list
					mail_adr.adr_values.sort()                                    # sort list
					write_list_to_file(mail_adr.adr_values, mail_lists[i])        # write list to file
					print(f"Added {new_mail_adr[:-1]} to file {mail_lists[i]}\n") # confirmation
					exit()
			# no mach was found for FILTER, so mail address cannot be saved
			print("usage: maillist.py [-a ADDADDRESS] [-f FILTER]")
			print(f"       You provided a wrong Argument to the -f Parameter. Please check your input: {addfilter}\n")
			exit()
		else:
			# mail address is not valid
			print("usage: maillist.py [-a ADDADDRESS] [-f FILTER]")
			print(f"       provided email address is not valid: {new_mail_adr}\n")
			exit()


def del_address(address, delfilter, mail_adrs, mail_lists)->None:
	""" 
	Deletes a mail address from the list 
	
	:param str address: email address to delete
	:param str delfilter: file where the address should be deleted
	:param list:MailAdr mail_adrs: address lists
	:param list:str mail_lists: list of files
	:return: Nothing
	:rtype: None
	"""
	if delfilter == None:
		print("usage: maillist.py [-d DELADDRESS] [-f FILTER]")
		print("       Use -f Parameter to specify in which file the mailaddress should be deleted.\n")
		exit()
	else:
		del_mail_adr = remove_semicolon(address)  # in case of an added semicolon, it will be removed, because it is not an part of the email address
		for i, mail_adr in enumerate(mail_adrs):                              # search for the mail_list file
			if mail_adr.adr_type.lower() == delfilter.lower():
				del_mail_adr = del_mail_adr+";"                               # add semicolon
				if check_is_in_list(mail_adr.adr_values, del_mail_adr):       # check if entry is in list
					print(f"{del_mail_adr[:-1]} not found in {mail_lists[i]}. Email not deleted.\n")
					exit()
				consent = input(f"Are you sure you want delete this line: {del_mail_adr} [y/N]:")
				if consent.lower() != "y":                                    # ask for consent to delete
					print(f"{del_mail_adr[:-1]} not deleted from file {mail_lists[i]}\n")
					exit()
				mail_adr.adr_values = del_from_list(mail_adr.adr_values, del_mail_adr) # delete from list
				mail_adr.adr_values.sort()                                    # sort list
				write_list_to_file(mail_adr.adr_values, mail_lists[i])        # write list to file
				print(f"{del_mail_adr[:-1]} deleted from file {mail_lists[i]}\n") # confirmation
				exit()
		# no mach was found for FILTER, so mail address cannot be saved
		print("usage: maillist.py [-d DELADDRESS] [-f FILTER]")
		print(f"       You provided a wrong Argument to the -f Parameter. Please check your input: {delfilter}\n")
		exit()


def check_list(func, funcfilter, mail_adrs, mail_lists)->None:
	""" 
	Checks the list. Two valid parameter are available: verify, double
	
	:param Func func: which function is selected. Is of type Func (ENUM)
	:param str funcfilter: select one file only
	:param list:MailAdr mail_adrs: address lists
	:param list:str mail_lists: list of files
	:return: Nothing
	:rtype: None
	"""
	if func == Func.double:
		check_double_in_list(funcfilter, mail_adrs, mail_lists)
	elif func == Func.verify:
		verify_list_entries(funcfilter, mail_adrs, mail_lists)
	else:
		# no mach was found for FUNC
		print("usage: maillist.py [-t FUNC] [-f FILTER]")
		print(f"       You must provide a valid Argument for the -t Parameter. Valid inputs are: double (searches for double instances of an email address and deletes it), verify (verifies all email addresses in the email files to be valid email-addresses).Please check your input: {func}\n")
		exit()


def check_double_in_list(funcfilter, mail_adrs, mail_lists)->None:
	""" 
	Checks if there are double entries 
	
	:param str funcfilter: select one file only
	:param list:MailAdr mail_adrs: address lists
	:param list:str mail_lists: list of files
	:return: Nothing
	:rtype: None
	"""
	adrs_all = []
	adrs_double = []
	isdouble = False
	checkdouble = ""
	if funcfilter == None:
		for i, mail_adr in enumerate(mail_adrs):  # create one big list of all files
			for j,adr in enumerate(mail_adr.adr_values):
				adrs_all.append((adr.lower(),i,j))# create a big list with tupes from text of the line, file id, and line id
		adrs_all.sort()                           # sort all email addresses by the text of the line (lower)
		for adr in adrs_all:                      # find all double items
			if adr[0] == checkdouble:
				adrs_double.append(adr)
			else:
				checkdouble = adr[0]
		# print out the double items by file
		for i, mail_adr in enumerate(mail_adrs):
			print("************************************************")
			print(f"*** doubles found in: {mail_adr.adr_type}")
			print("************************************************")
			for adr in adrs_double:
				if adr[1] == i:
					isdouble = True
					print (adr[0])
			if isdouble == False:
				print("None")
			isdouble = False
			
		# Ask if we should delete double items			
		if len(adrs_double) > 0:			
			consent = input("Do you want delete double items? The first item is preserved. [y/N]:")
			if consent.lower() != "y":
				print("nothing deleted\n")
				exit()
			else:
				adrs_double.sort(key=lambda tup: tup[2], reverse=True) # sort all entries by the line id of the list from the files - so the index will not change when deleting elements for the items still needed to be deleted
				for adr in adrs_double:
					del mail_adrs[adr[1]].adr_values[adr[2]]
				for i, mail_adr in enumerate(mail_adrs):               # save all the files
					write_list_to_file(mail_adr.adr_values, mail_lists[i])
				print("items deleted\n")
				exit()
	else:
		# only one file to check. file defined by funcfilter
		adrs_double = []
		isdouble = False
		checkdouble = ""
		fileId = 0
		for i, mail_adr in enumerate(mail_adrs):
			if mail_adr.adr_type.lower() == funcfilter.lower():
				print("************************************************")
				print(f"*** checking for doubles: {mail_adr.adr_type}")
				print("************************************************")
				fileid = i
				mail_adr.adr_values.sort()
				for adr_value in mail_adr.adr_values:
					if adr_value.lower() == checkdouble.lower():
						adrs_double.append(adr_value)
					else:
						checkdouble = adr_value
				if len(adrs_double) == 0:
					print("None")
				else:
					isdouble = True
					for adr in adrs_double:
						print(adr)
		
				# Ask if we should delete double items
				if isdouble:		
					consent = input("Do you want delete double items? [y/N]:")
					if consent.lower() != "y":
						print("nothing deleted\n")
						exit()
					else:
						adr_set = set(mail_adrs[fileid].adr_values)
						write_list_to_file(adr_set, mail_lists[fileid])
						print("double items removed.\n")
						exit()


def verify_list_entries(funcfilter, mail_adrs, mail_lists)->None:
	""" 
	Verify if mail addresses are valid 
	
	:param str funcfilter: select one file only
	:param list:MailAdr mail_adrs: address lists
	:param list:str mail_lists: list of files
	:return: Nothing
	:rtype: None
	"""
	# check all files for errors
	adrs_to_del = []
	istorepair = False
	if funcfilter == None:
		for mail_adr in mail_adrs:
			# find wrong items
			print("************************************************")
			print(f"*** checking {mail_adr.adr_type}:")
			print("************************************************")
			to_del = []
			for adr_value in mail_adr.adr_values:
				if check_line_validity(adr_value) == False:
					to_del.append(adr_value)
			if len(to_del) == 0:
				print("None")
			else:
				istorepair = True
				adrs_to_del.extend(to_del)
				for adr in to_del:
					print(adr)
		
		# Ask if we should delete wrong items			
		if istorepair:			
			consent = input("Do you want delete the wrong items? [y/N]:")
			if consent.lower() != "y":
				print("nothing deleted\n")
				exit()
			else:
				for i, mail_adr in enumerate(mail_adrs):
					for adr in adrs_to_del:
						try:
							mail_adr.adr_values.remove(adr)
						except ValueError:
							pass
					write_list_to_file(mail_adr.adr_values, mail_lists[i])
				print("items deleted\n")
				exit()
	else:
		# only one file to check. file defined by funcfilter
		adrs_to_del = []
		istorepair = False
		fileId = 0
		for i, mail_adr in enumerate(mail_adrs):               # search for the right mail_list file
			if mail_adr.adr_type.lower() == funcfilter.lower():
				print("************************************************")
				print(f"*** checking {mail_adr.adr_type}:")
				print("************************************************")
				fileid = i
				for adr_value in mail_adr.adr_values:
					if check_line_validity(adr_value) == False:
						adrs_to_del.append(adr_value)
				if len(adrs_to_del) == 0:
					print("None")
				else:
					istorepair = True
					for adr in adrs_to_del:
						print(adr)
		
				# Ask if we should delete wrong items
				if istorepair:		
					consent = input("Do you want delete the wrong items? [y/N]:")
					if consent.lower() != "y":
						print("nothing deleted\n")
						exit()
					else:
						for adr in adrs_to_del:
							try:
								mail_adrs[fileid].adr_values.remove(adr)
							except ValueError:
								pass
						write_list_to_file(mail_adrs[fileid].adr_values, mail_lists[fileid])
						print("items deleted\n")
						exit()


def move_mail(funcfilter, mail_adrs, mail_lists) -> None:
	""" 
	Moves provided email from one file to another
	
	:param list funcfilter: the input from commandline: 1. emailaddress 2. fromfile 3. tofile
	:param list mail_adrs: the mail addresses from the files. Type of the elements: MailAdr
	:param list mail_lists: list of filenames as defined in ini-file
	:return: Nothing
	:rtype: None
	"""
	fromfile = -1
	tofile = -1
	for i, mail_adr in enumerate(mail_adrs):
		if mail_adr.adr_type.lower() == funcfilter[1].lower():
			fromfile = i
		if mail_adr.adr_type.lower() == funcfilter[2].lower():
			tofile = i
	if fromfile == -1 or tofile == -1:  # no mach was found for FILTER(s)
		print("usage: maillist.py [-m EMAILADDRESS FROMFILE TOFILE]")
		print(f"       You provided some wrong Argument. FROMFILE or TOFILE not found. Please check your input: {funcfilter[1]}, {funcfilter[2]}\n")
		exit()
	for adr in mail_adrs[fromfile].adr_values:
		if (funcfilter[0].lower()+";") == adr.lower():               # check if email address (FUNCFILTER[0]) is in FROMFILE
			mail_adrs[fromfile].adr_values.remove(adr)               # remove item from FROMFILE
			mail_adrs[tofile].adr_values.append(funcfilter[0]+";")   # append item to TOFILE
			write_list_to_file(mail_adrs[fromfile].adr_values, mail_lists[fromfile])
			write_list_to_file(mail_adrs[tofile].adr_values, mail_lists[tofile])
			print("item moved\n")
			exit()
	print("usage: maillist.py [-m EMAILADDRESS FROMFILE TOFILE]")
	print(f"       Email not found in FROMFILE: {funcfilter[0]}\n")
	exit()
	
	
# ###################################################################
# MAIN
# ###################################################################
def main() -> None:
	### Config einlesen #############################################
	mail_lists = read_config()
	
	### Creates the Types from Filenames of the Mailinglists ########
	mail_list_types = get_mail_list_types(mail_lists)
	
	### Creating the list of MailAdr objects ########################
	mail_adrs:MailAdr = []
	for i, mail_list in enumerate(mail_lists):
		mail_adrs.append(MailAdr(mail_list_types[i], read_mail_list_file(mail_list)))
	#print(mail_adrs[1].adr_values)
		
	### Reading the parameters given with the call ##################
	# -s --search		eMail-Adresse nach Schlagwort suchen
	# -f --filter       Unterscheidung ob Aktion für test1 oder test2 angewandt werden soll
	# -a --add			eMail-Adresse hinzufügen
	# -d --delete		eMail-Adresse löschen
	# -t double         doppelt Einträge suchen und entfernen
	# -t verify         eMail-Adressen auf Gültigkeit prüfen
	# -m --move         eMail-Adresse von einer Datei in eine andere verschieben
    #                   eMail-Adressen werden ausgeben
	msg = "Manages lists of email addresses stored in files. Configure which files to use with maillist.ini file. The expected format of the email addresses within the files is: `someone@example.com;` \nEach address is in one line. Please take care that there is a semicolon at the end of each line."
	parser = ArgumentParser(description = msg)
	parser.add_argument("-s", dest="SEARCHSTRING", type=str, help="search for a string in the email addresses. Use -f to filter only one email address file.")
	parser.add_argument("-f", dest="FILTER", type=str, help="filter only one email address file")
	parser.add_argument("-a", dest="ADDADDRESS", type=str, help="add an email addresses. Use -f to define to which address file.")
	parser.add_argument("-d", dest="DELADDRESS", type=str, help="delete this email addresses. Use -f to define from which address file.")
	parser.add_argument("-t", dest="FUNC", type=Func, help="tests and corrects email address files. Use -f to specify which address file you select. Valid arguments: double - searches for double instances of an email address and deletes it, verify - verifies all email addresses in the email files to be valid email-addresses")
	parser.add_argument("-m", dest="MOVE", nargs=3, type=str, help="moves email from one addressfile to another. Usage: maillist.py -m someone@example.com fromfile tofile")
	args = parser.parse_args()
	#print(args)
	
	### Calculating the output ######################################
	if args.SEARCHSTRING != None:
		search_list(args.SEARCHSTRING, args.FILTER, mail_adrs)
		
	elif args.ADDADDRESS != None:
		add_address(args.ADDADDRESS, args.FILTER, mail_adrs, mail_lists)

	elif args.DELADDRESS != None:
		del_address(args.DELADDRESS, args.FILTER, mail_adrs, mail_lists)
				
	elif args.FUNC != None:
		check_list(args.FUNC, args.FILTER, mail_adrs, mail_lists)

	elif args.MOVE != None:
		move_mail(args.MOVE, mail_adrs, mail_lists)
			
	elif args.FILTER != None:
		filter_mail_list(mail_adrs, mail_list_filter=args.FILTER)

	else:
		for mail_adr in mail_adrs:
			print_mail_addresses(mail_adr.adr_values)


if __name__ == "__main__":
	main()
