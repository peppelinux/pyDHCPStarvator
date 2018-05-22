import random
import uuid
letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

dlenght = {
            1: 3,
            2: 6,
            3: 4,
            4: 5
          }

def random_uid():    
    name = []
    rlenght = random.choice(list(dlenght.keys()))
    for i in range(dlenght[rlenght]):
        name.append(random.choice(letters))
    return ''.join(name)


def random_hostname(wordlist='wordlist.txt', sep='-'):
    with open(wordlist, encoding='UTF-8') as wd:
        words = [i.replace('\n', '') for i in wd.readlines()]
    
    rchoice = random.choice(words)
    u = random_uid()
    if rchoice == 'android':
        return rchoice+sep+str(uuid.uuid4())
    if random.choice(list(dlenght.keys())) % 2:
        return u+sep+rchoice
    else:
        return (u+sep+rchoice).upper()
