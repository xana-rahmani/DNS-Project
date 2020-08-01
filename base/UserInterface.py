import time
from base import Client

print("#########################################")
print("#\t\t   \t\t\t#")
print("#\t\tDNS Project\t\t#")
print("#\t\t   \t\t\t#")
print("#########################################\n")

time.sleep(2)

print("Commands: ")
print("\t1. g-C")
print("\t\tDescription: generate certificaat")
print("\t\tArgs: name, national_code")

print("\t2. g-AS_ticket")
print("\t\tDescription: generate AS ticket")
print("\t\tArgs: national_code")

print("\t3. vote")
print("\t\tDescription: sens vote")
print("\t\tArgs: candidate_id")

print("\t4. exit")
print("\t\tDescription: close program")

while True:
    print("$ ", end="")
    temp = input().split()
    if temp[0] == "g-C":
        if len(temp) != 3:
            print("---- Wrong Command ----")
            continue
        Client.generateCertificaat(name=temp[1], national_code=temp[2])

    elif temp[0] == "g-AS_ticket":
        if len(temp) != 2:
            print("---- Wrong Command ----")
            continue
        Client.generate_AS_ticket(national_code=temp[1])

    elif temp[0] == "vote":
        if len(temp) != 2:
            print("---- Wrong Command ----")
            continue
        Client.vote(candidate_id=temp[1])

    elif temp[0] == "exit":
        print("#### Close Program ####")
        break

    else:
        print("---- Wrong Command ----")

# from base import UserInterface
# g-C xana 9075529379
# g-AS_ticket 9075529379
# vote 1