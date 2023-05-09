#get required libraries for AD operations
from getpass import getpass
import sys
import subprocess
from ldap3 import Server, Connection, ObjectDef, Reader, ALL
from pyad import pyadutils, adcontainer, adgroup, adcomputer
from pyad.adquery import ADQuery

#check for network connection, suppress output, give success message if connection detected, exit if not
def check_network_connection():
    try:
        subprocess.check_output("ping -n 1 www.google.com", shell=True)
        print("Network connection detected.")
        return True
    except:
        print("No network connection detected. Please connect to the network and try again.")
        return False
    
#check for network connection, exit if not detected
if not check_network_connection():
    input("Press enter to exit.")
    sys.exit()

#prompt for domain name, admin username, and password; verify credentials and repeat if incorrect
while True:
    domain_name = input("Enter domain name: ")
    domain_admin = input("Enter domain admin username: ")
    domain_admin_password = getpass("Enter domain admin password: ")

    try:
        server = Server(domain_name, get_info=ALL)
        # Use simple_bind authentication with userPrincipalName (UPN) format
        connection = Connection(server, user=f"{domain_admin}@{domain_name}", password=domain_admin_password)
        
        if connection.bind():
            print("AD connection and credentials verified.")
            break
        else:
            print("Domain name or admin credentials incorrect. Please try again.")
    except Exception as e:
        print("Error connecting to the domain. Please try again.")
        print(f"Exception: {e}")

domain_prefix, domain_suffix = domain_name.split(".")
new_computer_name = input("Enter new computer name: ")

# Set default domain name, username, and password for pyad
pyadutils.set_defaults(ldap_server=domain_name, username=domain_admin, password=domain_admin_password)

def join_domain(domain, ou_path, username, password, new_computer_name):
    ps_command = f"""
    $securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ('{username}', $securePassword)
    Add-Computer -DomainName {domain} -Credential $credential -OUPath '{ou_path}' -NewName '{new_computer_name}'
    """
    try:
        subprocess.run(["powershell.exe", "-Command", ps_command], check=True)
        print("Computer joined to the domain successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error joining the domain: {e}")

def select_ou(current_dn=None, ou_path=None):
    if not current_dn:
        current_dn = f"DC={domain_prefix},DC={domain_suffix}"

    ou_list = adcontainer.ADContainer.from_dn(current_dn).get_children()
    ou_list = [ou for ou in ou_list if "organizationalUnit" in (ou.get_attribute("objectClass") or [])]
    ou_names = [ou.get_attribute("name")[0].strip("[]'") for ou in ou_list if ou.get_attribute("name") is not None]

    if ou_path:
        print(f"Current OU Path: {ou_path.strip('[]')}")
    print(f"Available OU's in {current_dn}:")
    for i, ou_name in enumerate(ou_names, start=1):
        print(f"{i}. {ou_name}")

    print("0. Select current OU and exit")
    print("-1. Go back to the previous level")
    print("-2. Exit without selecting an OU")

    choice = int(input("Enter the number corresponding to your choice: "))

    if choice > 0 and choice <= len(ou_list):
        selected_ou = ou_list[choice - 1]
        new_dn = selected_ou.dn
        if ou_path:
            new_ou_path = f"OU={ou_names[choice-1]},{ou_path.strip('[]')}"
        else:
            new_ou_path = f"OU={ou_names[choice-1]},{current_dn}"
        return select_ou(new_dn, new_ou_path)
    elif choice == 0:
        return ou_path.strip('[]') if ou_path else current_dn
    elif choice == -1:
        if ou_path:
            parent_dn, _, ou_path = ou_path.rpartition("/")
            parent_dn, _, _ = parent_dn.rpartition(",")
            return select_ou(parent_dn, ou_path)
        else:
            return select_ou()
    elif choice == -2:
        return None
    else:
        print("Invalid choice. Please try again.")
        return select_ou(current_dn, ou_path)

def add_group():
    while True:
        group_search = input("Enter search term for security group to add computer to. Type 'exit' to exit: ")

        if group_search.lower() == "exit":
            return
        else:
            try:
                search_base = f"DC={domain_prefix},DC={domain_suffix}"
                search_filter = f"(&(objectCategory=group)(name=*{group_search}*))"

                group_obj = ObjectDef('group', connection)
                group_reader = Reader(connection, group_obj, search_base, search_filter)
                group_reader.search()
                group_list = [(group_entry.entry_attributes_as_dict['name'][0], group_entry.entry_dn) for group_entry in group_reader]

                if group_list:
                    print("Available groups matching \'{}\" in {}".format(group_search, domain_name))
                    for i, (group_name, group_dn) in enumerate(group_list, start=1):
                        print(f"{i}. {group_name}")

                    print("0. Search again")
                    print("-1. Exit")

                    choice = int(input("Enter the number corresponding to your choice: "))

                    if choice > 0 and choice <= len(group_list):
                        group_name, group_dn = group_list[choice - 1]
                        group = adgroup.ADGroup.from_dn(group_dn)
                        computer = adcomputer.ADComputer.from_cn(new_computer_name)
                        if computer:
                            group.add_members(computer)
                            print(f"Computer {new_computer_name} added to the group {group_name}.")
                        else:
                            print(f"Computer {new_computer_name} not found.")
                    elif choice == 0:
                        continue
                    elif choice == -1:
                        break
                    else:
                        print("Invalid choice. Please try again.")
                        continue

                else:
                    print("No groups found with search term {}".format(group_search))

            except Exception as e:
                print(f"Error searching for groups: {e}")


# Join the computer to the domain
ou_path = select_ou()
join_domain(domain_name, ou_path, domain_admin, domain_admin_password, new_computer_name)

# Add the computer to the security groups
add_group()

# Restart the computer
print("Please restart your computer for changes to take effect.")