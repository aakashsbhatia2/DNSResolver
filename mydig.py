# libraries imported
import dns.query
import dns.message
import datetime

#initialising sum = 0 to store number of bytes in the answer section
sum = 0

#User is prompted to enter a URL
addr = input('Please enter website URL: ')

#User is prompted to enter type of resolution
type = input('Please enter resolution type: ')

#Printing question section as per format
print('QUESTION SECTION:\n')
print(addr,'\tIN\t', type,'\n')

#t1 indicates the time at which the query is inititiated
t1 = datetime.datetime.now()

#initialising set to hold unique values of the answer obtained
answer = set()

#initialising the list of root IP addresses
all_servers = list()
all_servers.append('198.41.0.4')
all_servers.append('199.9.14.201')
all_servers.append('192.33.4.12')
all_servers.append('199.7.91.13')
all_servers.append('192.203.230.10')
all_servers.append('192.5.5.241')
all_servers.append('192.112.36.4')
all_servers.append('198.97.190.53')
all_servers.append('192.36.148.17')
all_servers.append('192.58.128.30')
all_servers.append('193.0.14.129')
all_servers.append('199.7.83.42')
all_servers.append('202.12.27.33')

#if the user selects resolution of A type records
if type=='A':

    # request message to be sent to each server during the DNSSEC protocol implementation
    request = dns.message.make_query(addr, rdtype=1, rdclass=1)

    # Running a loop through all the root servers to obtain the next IP address
    for servers in all_servers:

        # querying a response to the request sent
        response = dns.query.udp(request, servers)

        #loop which runs through each item in the response.addition section
        for n in response.additional:

            # splitting the string in the response.additional section to retreive the IP address
            ip = str(n).split()[-1]

            # performing a check to identify IP address (since records are of type xyz.xyz.xyz.xyz and xyz:xyz:xyz:xyz)
            if ip.__contains__('.'):

                # appending the newly identified IP address to the list of IP addresses (all_servers)
                all_servers.append(ip)

                # reducing the list of IP addresses to increase efficiency
                del all_servers[0:len(all_servers)-3]

        #check if answer section is empty or not (to identify whether we have reached the goal server)
        if response.answer.__len__() != 0:

            #running a loop through the answer section to store the values in the set
            for n in response.answer:
                answer = n

    #Printing answer section as per format
    print('ANSWER SECTION:\n')
    print(answer,'\n')

elif type=='MX':

    # request message to be sent to each server during the DNSSEC protocol implementation
    request = dns.message.make_query(addr, rdtype=15, rdclass=1)

    # Running a loop through all the root servers to obtain the next IP address
    for servers in all_servers:

        # querying a response to the request sent
        response = dns.query.udp(request, servers)

        # loop which runs through each item in the response.addition section
        for n in response.additional:

            # splitting the string in the response.additional section to retreive the IP address
            ip = str(n).split()[-1]

            # performing a check to identify IP address (since records are of type xyz.xyz.xyz.xyz and xyz:xyz:xyz:xyz)
            if ip.__contains__('.'):
                # appending the newly identified IP address to the list of IP addresses (all_servers)
                all_servers.append(ip)

                # reducing the list of IP addresses to increase efficiency
                del all_servers[0:len(all_servers) - 3]

        # check if answer section is empty or not (to identify whether we have reached the goal server)
        if response.answer.__len__() != 0:

            # running a loop through the answer section to store the values in the set
            for n in response.answer:
                answer = n

    # Printing answer section as per format
    print('ANSWER SECTION:\n')
    print(answer,'\n')

elif type=='NS':

    # request message to be sent to each server during the DNSSEC protocol implementation
    request = dns.message.make_query(addr, rdtype=2, rdclass=1)

    # Running a loop through all the root servers to obtain the next IP address
    for servers in all_servers:

        # querying a response to the request sent
        response = dns.query.udp(request, servers)

        # loop which runs through each item in the response.authority section
        for n in response.additional:

            # splitting the string in the response.additional section to retrieve the IP address
            ip = str(n).split()[-1]

            # performing a check to identify IP address (since records are of type xyz.xyz.xyz.xyz and xyz:xyz:xyz:xyz)
            if ip.__contains__('.'):

                # appending the newly identified IP address to the list of IP addresses (all_servers)
                all_servers.append(ip)

                # reducing the list of IP addresses to increase efficiency
                del all_servers[0:len(all_servers) - 3]

        # check if authority section contains SOA record
        for n in response.authority:
            if str(n).split()[3] == 'SOA':
                answer = n

    # Printing answer section as per format
    print('ANSWER SECTION:\n')
    print(answer,'\n')

#noting the time at the end of execution and printing the difference to obtain execution time
t2 = datetime.datetime.now()
t = t2-t1
print('Query Time: ', t.microseconds/1000)

#printing the date and time at which the program is run
print('\nWhen: ', datetime.datetime.now())

#printing the number of bytes stored in the answer section
print ('\nMSG SIZE rcvd: ', response.answer.__sizeof__())










