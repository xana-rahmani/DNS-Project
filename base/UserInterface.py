import time
from base import Client
from CA.models import User
from CA.models import Certificaat
from AS.models import RestrictedNationalCodes
from VS.models import Candidates
from VS.models import Votes
print("#########################################")
time.sleep(0.4)
print("#\t\t   \t\t\t#")
time.sleep(0.4)
print("#\t\tDNS Project\t\t#")
time.sleep(0.4)
print("#\t\t   \t\t\t#")
time.sleep(0.4)
print("#########################################\n\n")

time.sleep(2)

print(" **********  DATA IN DATA BASE  ********** ")
users = [('xana', '3850230478'), ('khashayar', '100000000'),  ('armin', '100000001'),
         ('sadi', '100000002'), ('hafez', '100000003'), ('payman', '100000004'), ('ramin', '100000005'),
         ('arya', '100000006'), ('amir', '100000007'), ('arman', '100000008'), ('sahand', '100000009')]

restrictedNationalCodes = [('amir', '100000007'), ('payman', '100000004')]
candidates = [('xana', '3850230478'), ('khashayar', '100000000'), ('sahand', '100000009')]

print("\tUsers Information")
User.objects.all().delete()
Certificaat.objects.all().delete()
for user in users:
    print("\t\t", user[0], "\t.... ", user[1])
    userObject = User(name=user[0], national_code=user[1])
    userObject.save()

print("\n\tRestricted National Codes")
RestrictedNationalCodes.objects.all().delete()
for RNCode in restrictedNationalCodes:
    print("\t\t", RNCode[0], "\t.... ", RNCode[1])
    RNCodeObject = RestrictedNationalCodes(national_code=RNCode[1])
    RNCodeObject.save()

print("\n\tCandidates")
Candidates.objects.all().delete()
Votes.objects.all().delete()
candidate_id = 1
for candidate in candidates:
    print("\t\t", candidate[0], "\t.... ", candidate[1], "\t ID: ",candidate_id)
    candidateObject = Candidates(candidate_id=candidate_id)
    candidateObject.save()
    candidate_id += 1

print("\n ************************************** \n")
time.sleep(2)

print("Commands: ")
print("\t1. g-C")
print("\t\tDescription: generate certificaat")
print("\t\tArgs: name, national_code")
time.sleep(0.5)
print("\t2. g-AS_ticket")
print("\t\tDescription: generate AS ticket")
print("\t\tArgs: national_code")
time.sleep(0.5)
print("\t3. vote")
print("\t\tDescription: send vote")
print("\t\tArgs: candidate_id")
time.sleep(0.5)
print("\t4. seeVote")
print("\t\tDescription: see vote")
time.sleep(0.5)
print("\t5. exit")
print("\t\tDescription: close program")

while True:
    print("$ ", end="")
    temp = input().split()
    if len(temp) == 0:
        continue
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

    elif temp[0] == "seeVote":
        if len(temp) != 1:
            print("---- Wrong Command ----")
            continue
        Client.seeVote()

    elif temp[0] == "exit":
        print("#### Close Program ####")
        break

    else:
        print("---- Wrong Command ----")

# from base import UserInterface
# g-C ramin 100000005
# g-AS_ticket 100000005
# vote 1
# seeVote

# g-C amir 100000007
# g-AS_ticket 100000007
