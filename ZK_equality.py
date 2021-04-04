#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#pip install git+https://github.com/spring-epfl/zksk


# In[1]:


from zksk import Secret, DLRep
from zksk import utils


# In[54]:


def ZK_equality(G,H):

##Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    # Setup: generate a secret randomizer.
    
    # m is the secret bit.
    m = Secret(utils.get_random_num(bits=2))
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))

    
    #print("this is r1 and r2:", r1.value,",",r2.value)
    C1 = r1.value* G
    #print("this is C1:", C1)

    C2 = m.value * G + r1.value * H
    D1 = r2.value * G
    D2 = m.value * G + r2.value * H
  
  

    # A Pedersen commitment to the secret bit.   
    
##Generate a NIZK proving equality of the plaintexts 

    stmt = DLRep(C1,r1*G) & DLRep(C2,m*G+r1*H) & DLRep(D1,r2*G) & DLRep(D2,m*G+r2*H)
    zk_proof = stmt.prove()
    
    
    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof


# In[53]:





