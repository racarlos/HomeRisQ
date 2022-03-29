def getSubsetComputationAllocation(vulnCount, coreCount):

    # Add Responsibilities based on number of Cores
    responsibilities = []

    for i in range(coreCount): 
        responsibilities.append([])

    index = 0
    flip = False
    for i in range(vulnCount):

        print(f'[{index}-{flip}] ',end='')

        if flip is False:
            responsibilities[index].append(i)
            index += 1 
        elif flip is True:
            responsibilities[index].append(i)
            index -= 1


        if index == coreCount and flip is False:
            index = 3
            flip = True
            continue 
        elif index == -1 and flip is True:
            index = 0
            flip = False
        continue

    return responsibilities

vulnCount = 60
coreCount = 4

responsibilities = getSubsetComputationAllocation(vulnCount,coreCount)

for arr in responsibilities:
    sum = 0
    for i in range(len(arr)):
        sum += arr[i]

    print(f'{responsibilities.index(arr)}: {sum}')