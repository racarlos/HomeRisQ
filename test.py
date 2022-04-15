import re

#Converts CVSS Vector to Vector String
def splitVector(vector):

    vectorList = vector.split("/")

    for i in range(len(vectorList)):
        vectorList[i] = vectorList[i].split(":")

    return vectorList

def transformVector(vector):
    vectorList = splitVector(vector)
    newVector = ""
    print(vectorList)

    for i in range(len(vectorList)): 
        metric = vectorList[i]
    
        if(metric[0] == 'AV'):
            if metric[1] == 'P':	                                # Convert P to L
                newVector += 'AV:L' + '/'
            else:
                newVector += 'AV:' + metric[1] + '/'

        elif(metric[0] == 'AC'):                                    # Convert L to either L or M

            if metric[1] == 'L' and vectorList[3][1] == 'N':	   
                newVector += 'AC:L/'
            elif metric[1] == 'L' and vectorList[3][1] == 'R':	   
                newVector += 'AC:M/'
            else:
                newVector += 'AC:' + metric[1] + '/'

        elif(metric[0] == 'PR'):                                    # Convert Privileges Required to Authentication
            
            if metric[1] == 'H':	                                # High to multiple
                newVector += 'Au:M/'
            if metric[1] == 'L':	                                # Low to Single
                newVector += 'Au:S/'
            if metric[1] == 'N':	                                # None to None
                newVector += 'Au:N/'
        
        elif metric[0] == 'C' or metric[0] == 'I' or metric[0] == 'A':

            if metric[1] == 'H':	                                # High to Complete
                newVector += metric[0] + ':C' + '/'
            if metric[1] == 'L':	                                # Low to Partial
                newVector += metric[0] + ':P' + '/'
            if metric[1] == 'N':	                                # None to None
                newVector += metric[0] + ':N' + '/'
    
    newVector = newVector[:-1]
    print(newVector)





vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
transformVector(vector)